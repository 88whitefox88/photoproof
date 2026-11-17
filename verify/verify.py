#!/usr/bin/env python3
"""
Проверка пакета фотофиксации «ФотоДоказ».

Использование:
    python verify.py ПАКЕТ [--tsa-ca CA.pem ...] [--apple-root Apple_App_Attestation_Root_CA.pem]

ПАКЕТ — ZIP-архив, экспортированный из приложения, или распакованная папка.

Проверяется:
  1. SHA-256 каждого файла совпадает с паспортом manifest.json;
  2. подпись manifest.json ключом устройства (ECDSA P-256 / SHA-256);
  3. метки доверенного времени RFC 3161: выданы именно на эти файлы, подпись службы
     криптографически верна, сертификат предназначен для штампов времени;
     цепочка до корня проверяется через OpenSSL по системному набору корневых сертификатов
     (DigiCert, Sectigo) и сертификатам из --tsa-ca (FreeTSA: https://freetsa.org/files/cacert.pem);
  4. аттестация Apple App Attest и подпись паспорта аттестованным ключом
     (цепочка до корня Apple — при указании --apple-root).

Зависимости:  pip install -r requirements.txt   (cryptography, asn1crypto, cbor2)
Код возврата: 0 — ошибок нет, 1 — найдены ошибки, 2 — неверный вызов.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from asn1crypto import tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
except ImportError:
    print("Не установлены зависимости. Выполните: pip install cryptography asn1crypto cbor2")
    sys.exit(2)

APPLE_ROOT_URL = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem"
APP_ATTEST_NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


class Report:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, title: str, detail: str = "") -> None:
        self._line("[ OK ]", title, detail)

    def fail(self, title: str, detail: str = "") -> None:
        self.failures += 1
        self._line("[ОШИБКА]", title, detail)

    def warn(self, title: str, detail: str = "") -> None:
        self.warnings += 1
        self._line("[ ?? ]", title, detail)

    def info(self, title: str, detail: str = "") -> None:
        self._line("[ -- ]", title, detail)

    @staticmethod
    def _line(mark: str, title: str, detail: str) -> None:
        print(f"{mark} {title}" + (f": {detail}" if detail else ""))

    @staticmethod
    def section(title: str) -> None:
        print(f"\n== {title} ==")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------- пакет

def open_package(path: Path) -> tuple[Path, Path | None]:
    """Возвращает (папка с manifest.json, временная папка для удаления)."""
    if path.is_file() and zipfile.is_zipfile(path):
        tmp = Path(tempfile.mkdtemp(prefix="photoproof_"))
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                target = (tmp / member.filename).resolve()
                if not str(target).startswith(str(tmp.resolve())):
                    raise ValueError(f"небезопасный путь в архиве: {member.filename}")
            archive.extractall(tmp)
        return find_manifest_dir(tmp), tmp
    if path.is_dir():
        return find_manifest_dir(path), None
    raise ValueError("укажите ZIP-архив или папку пакета")


def find_manifest_dir(root: Path) -> Path:
    if (root / "manifest.json").is_file():
        return root
    candidates = [p.parent for p in root.rglob("manifest.json") if "__MACOSX" not in p.parts]
    if len(candidates) != 1:
        raise ValueError("manifest.json не найден (или найдено несколько)")
    return candidates[0]


# ---------------------------------------------------------------- проверки

def check_files(pkg: Path, manifest: dict, r: Report) -> None:
    r.section("1. Контрольные суммы файлов")
    for entry in manifest["files"]:
        path = pkg / entry["name"]
        if not path.is_file():
            r.fail(entry["name"], "файл отсутствует")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual == entry["sha256"]:
            r.ok(entry["name"], f"SHA-256 {actual}")
        else:
            r.fail(entry["name"], f"SHA-256 не совпадает: в паспорте {entry['sha256']}, фактически {actual}")


def check_signature(pkg: Path, manifest: dict, manifest_bytes: bytes, r: Report) -> None:
    r.section("2. Подпись паспорта ключом устройства")
    signing = manifest["signing"]
    try:
        key = serialization.load_pem_public_key((pkg / signing["publicKeyFile"]).read_bytes())
        signature = (pkg / signing["signatureFile"]).read_bytes()
    except (OSError, ValueError) as error:
        r.fail("Ключ или подпись", str(error))
        return
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(spki).hexdigest()
    if fingerprint == signing["publicKeySpkiSha256"]:
        r.ok("Открытый ключ", f"отпечаток {fingerprint}")
    else:
        r.fail("Открытый ключ", "отпечаток не совпадает с паспортом")
    try:
        key.verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
        storage = "Secure Enclave" if signing.get("keyStorage") == "secure-enclave" else signing.get("keyStorage")
        r.ok("Подпись manifest.json", f"{signing['algorithm']}, ключ хранится: {storage}")
    except InvalidSignature:
        r.fail("Подпись manifest.json", "подпись НЕ соответствует паспорту")


def parse_tsr(data: bytes):
    response = tsp.TimeStampResp.load(data)
    status = response["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise ValueError(f"статус ответа службы: {status}")
    signed_data = response["time_stamp_token"]["content"]
    tst_info = signed_data["encap_content_info"]["content"].parsed
    return signed_data, tst_info


def verify_cms_signature(signed_data) -> x509.Certificate:
    """Проверяет подпись службы времени над TSTInfo. Возвращает сертификат подписанта."""
    signer = signed_data["signer_infos"][0]
    certificates = [c.chosen for c in (signed_data["certificates"] or []) if c.name == "certificate"]
    sid = signer["sid"]
    signer_cert = None
    for cert in certificates:
        if sid.name == "issuer_and_serial_number":
            ias = sid.chosen
            if cert.issuer == ias["issuer"] and cert.serial_number == ias["serial_number"].native:
                signer_cert = cert
        elif sid.name == "subject_key_identifier" and cert.key_identifier == sid.chosen.native:
            signer_cert = cert
    if signer_cert is None:
        raise ValueError("сертификат службы не включен в метку")

    digest_name = signer["digest_algorithm"]["algorithm"].native
    hash_alg = HASHES[digest_name]()
    content = signed_data["encap_content_info"]["content"].contents
    signed_attrs = signer["signed_attrs"]
    if signed_attrs.native:
        message_digest = next(a["values"][0].native for a in signed_attrs if a["type"].native == "message_digest")
        h = hashlib.new(digest_name)
        h.update(content)
        if h.digest() != message_digest:
            raise ValueError("message-digest не совпадает с содержимым метки")
        to_verify = b"\x31" + signed_attrs.dump()[1:]
    else:
        to_verify = content

    cert = x509.load_der_x509_certificate(signer_cert.dump())
    public_key = cert.public_key()
    signature = signer["signature"].native
    algorithm = signer["signature_algorithm"].signature_algo
    if algorithm == "rsassa_pkcs1v15":
        public_key.verify(signature, to_verify, padding.PKCS1v15(), hash_alg)
    elif algorithm == "rsassa_pss":
        params = signer["signature_algorithm"]["parameters"]
        public_key.verify(signature, to_verify,
                          padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=params["salt_length"].native), hash_alg)
    elif algorithm == "ecdsa":
        public_key.verify(signature, to_verify, ec.ECDSA(hash_alg))
    else:
        raise ValueError(f"неподдерживаемый алгоритм подписи {algorithm}")
    return cert


SYSTEM_CA_BUNDLES = [
    Path(r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt"),  # Git for Windows
    Path("/etc/ssl/certs/ca-certificates.crt"),                          # Debian/Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),                            # RHEL/Fedora
    Path("/etc/ssl/cert.pem"),                                           # macOS
]


def find_openssl() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    git_openssl = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    return str(git_openssl) if git_openssl.is_file() else None


def openssl_verify(token: Path, digest_hex: str, ca_files: list[Path]) -> tuple[bool, str]:
    openssl = find_openssl()
    if not openssl:
        return False, "openssl не найден"
    for ca in ca_files:
        result = subprocess.run([openssl, "ts", "-verify", "-digest", digest_hex, "-in", str(token), "-CAfile", str(ca)],
                                capture_output=True, text=True)
        if result.returncode == 0:
            return True, f"OpenSSL: Verification: OK (корневые сертификаты: {ca})"
    return False, "не удалось построить цепочку до указанных корневых сертификатов (добавьте корень этой службы через --tsa-ca)"


def check_token(path: Path, expected: bytes, label: str, ca_files: list[Path], r: Report):
    try:
        signed_data, tst = parse_tsr(path.read_bytes())
    except Exception as error:  # noqa: BLE001
        r.fail(label, f"метка не читается: {error}")
        return None
    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256" or imprint["hashed_message"].native != expected:
        r.fail(label, "метка выдана на ДРУГОЙ файл")
        return None
    gen_time = tst["gen_time"].native
    try:
        cert = verify_cms_signature(signed_data)
        subject = cert.subject.rfc4514_string()
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            is_tsa = x509.oid.ExtendedKeyUsageOID.TIME_STAMPING in eku
        except x509.ExtensionNotFound:
            is_tsa = False
        r.ok(label, f"{gen_time.isoformat()} — подпись службы верна ({subject})")
        if not is_tsa:
            r.warn(label, "сертификат службы без назначения timeStamping")
    except Exception as error:  # noqa: BLE001
        r.fail(label, f"подпись службы не прошла проверку: {error}")
        return gen_time
    if ca_files:
        ok, detail = openssl_verify(path, expected.hex(), ca_files)
        (r.ok if ok else r.warn)(label + " — цепочка сертификатов", detail)
    return gen_time


def check_timestamps(pkg: Path, manifest: dict, manifest_bytes: bytes, ca_files: list[Path], r: Report) -> None:
    r.section("3. Метки доверенного времени (RFC 3161)")
    original = next((f for f in manifest["files"] if f["role"] == "original"), None)
    for entry in manifest.get("timestamps", []):
        check_token(pkg / entry["file"], bytes.fromhex(original["sha256"]),
                    f"{entry['file']} (на снимок)", ca_files, r)
    if not manifest.get("timestamps"):
        r.warn("Метки на снимок", "не получены в момент съемки: " + "; ".join(manifest.get("timestampErrors") or []))
    tokens = sorted((pkg / "tsa").glob("manifest_*.tsr")) if (pkg / "tsa").is_dir() else []
    for token in tokens:
        check_token(token, sha256(manifest_bytes), f"tsa/{token.name} (на паспорт)", ca_files, r)
    if not tokens:
        r.warn("Метки на паспорт", "отсутствуют")
    if not ca_files:
        r.info("Цепочки сертификатов служб", "не проверялись (укажите --tsa-ca)")

    clock = manifest.get("clockCheck")
    if clock:
        if clock["deviceClockWithinTolerance"]:
            r.ok("Сверка часов устройства",
                 f"расхождение с эталоном {clock['reference']} в пределах ±{clock['toleranceSeconds']:.0f} с")
        else:
            offset = (clock["deviceOffsetMinSeconds"] + clock["deviceOffsetMaxSeconds"]) / 2
            r.warn("Сверка часов устройства",
                   f"часы отличались от эталона на {offset:+.1f} с; в штампе время по эталону {clock['estimatedCaptureTimeUTC']}")


def check_app_attest(pkg: Path, manifest: dict, manifest_bytes: bytes, apple_root: Path | None, r: Report) -> None:
    r.section("4. Apple App Attest")
    info = manifest["signing"].get("appAttest")
    if not info:
        r.info("App Attest", "не использовался (устройство не поддерживает или аттестация не была готова)")
        return
    try:
        import cbor2
    except ImportError:
        r.warn("App Attest", "не установлен пакет cbor2 (pip install cbor2)")
        return
    try:
        attestation = cbor2.loads((pkg / info["attestationFile"]).read_bytes())
        challenge = (pkg / info["challengeFile"]).read_bytes()
    except (OSError, ValueError) as error:
        r.fail("Аттестация", str(error))
        return
    if attestation.get("fmt") != "apple-appattest":
        r.fail("Аттестация", f"неизвестный формат {attestation.get('fmt')}")
        return

    x5c = attestation["attStmt"]["x5c"]
    auth_data: bytes = attestation["authData"]
    leaf = x509.load_der_x509_certificate(x5c[0])
    intermediate = x509.load_der_x509_certificate(x5c[1])
    try:
        intermediate.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
        r.ok("Сертификат ключа", "подписан промежуточным сертификатом Apple")
    except InvalidSignature:
        r.fail("Сертификат ключа", "подпись промежуточного сертификата неверна")
    if apple_root:
        root = x509.load_pem_x509_certificate(apple_root.read_bytes())
        try:
            root.public_key().verify(intermediate.signature, intermediate.tbs_certificate_bytes,
                                     ec.ECDSA(intermediate.signature_hash_algorithm))
            r.ok("Цепочка Apple", f"до корня {root.subject.rfc4514_string()}")
        except InvalidSignature:
            r.fail("Цепочка Apple", "промежуточный сертификат не подписан указанным корнем Apple")
    else:
        r.warn("Цепочка Apple", f"корень не проверен — скачайте {APPLE_ROOT_URL} и укажите --apple-root")

    nonce = sha256(auth_data + sha256(challenge))
    try:
        extension = leaf.extensions.get_extension_for_oid(APP_ATTEST_NONCE_OID).value.value
        (r.ok if extension.endswith(nonce) else r.fail)("Nonce аттестации",
                                                         "совпадает" if extension.endswith(nonce) else "не совпадает")
    except x509.ExtensionNotFound:
        r.fail("Nonce аттестации", "расширение отсутствует")

    public_key = leaf.public_key()
    point = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = sha256(point)
    (r.ok if base64.b64decode(info["keyId"]) == key_id else r.fail)("Идентификатор ключа", info["keyId"])

    rp_id_hash = auth_data[:32]
    aaguid = auth_data[37:53]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_len]
    environment = {b"appattest\x00\x00\x00\x00\x00\x00\x00": "production",
                   b"appattestdevelop": "development"}.get(aaguid, "неизвестная")
    r.info("Среда App Attest", environment)
    if cred_id != key_id:
        r.fail("authData", "credentialId не совпадает с ключом")
    app_id = manifest["application"].get("appId")
    if app_id:
        (r.ok if sha256(app_id.encode()) == rp_id_hash else r.fail)("Идентификатор приложения", app_id)
    else:
        r.warn("Идентификатор приложения", "не записан в паспорте")

    assertion_path = pkg / info["assertionFile"]
    if not assertion_path.is_file():
        r.fail("Подпись паспорта App Attest", "файл отсутствует")
        return
    assertion = cbor2.loads(assertion_path.read_bytes())
    assertion_auth = assertion["authenticatorData"]
    try:
        public_key.verify(assertion["signature"], sha256(assertion_auth + sha256(manifest_bytes)), ec.ECDSA(hashes.SHA256()))
        if assertion_auth[:32] != rp_id_hash:
            r.fail("Подпись паспорта App Attest", "выдана для другого приложения")
        else:
            counter = int.from_bytes(assertion_auth[33:37], "big")
            r.ok("Подпись паспорта App Attest", f"верна (счетчик {counter})")
    except InvalidSignature:
        r.fail("Подпись паспорта App Attest", "подпись НЕ соответствует паспорту")


def print_summary(manifest: dict) -> None:
    capture = manifest["capture"]
    print(f"Пакет фотофиксации № {manifest['evidenceId']}")
    print(f"  Время по часам устройства: {capture['deviceTimeLocal']} ({capture['timeZone']})")
    place = manifest.get("place")
    if place:
        line = f"  Координаты: {place['latitude']:.6f}, {place['longitude']:.6f} ±{place['horizontalAccuracyMeters']:.0f} м"
        if place.get("address"):
            line += f" — {place['address']}"
        print(line)
        if place.get("isSimulatedBySoftware"):
            print("  ВНИМАНИЕ: iOS сообщила о программной подмене координат")
    hw, app = manifest["hardware"], manifest["application"]
    print(f"  Устройство: {hw['model']}, {hw['systemName']} {hw['systemVersion']}")
    print(f"  Приложение: {app['name']} {app['version']} ({app.get('appId') or app['bundleId']})")
    print(f"  Журнал устройства: запись № {manifest['journal']['sequence']}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Проверка пакета фотофиксации «ФотоДоказ»")
    parser.add_argument("package", type=Path, help="ZIP-архив или папка пакета")
    parser.add_argument("--tsa-ca", type=Path, action="append", default=[],
                        help="корневой сертификат службы времени (PEM); можно указать несколько раз")
    parser.add_argument("--apple-root", type=Path, help="Apple_App_Attestation_Root_CA.pem")
    args = parser.parse_args()
    ca_files = list(args.tsa_ca) + [p for p in SYSTEM_CA_BUNDLES if p.is_file()][:1]

    try:
        pkg, tmp = open_package(args.package)
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        print(f"Не удалось открыть пакет: {error}")
        return 2
    try:
        manifest_bytes = (pkg / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        report = Report()
        print_summary(manifest)
        check_files(pkg, manifest, report)
        check_signature(pkg, manifest, manifest_bytes, report)
        check_timestamps(pkg, manifest, manifest_bytes, ca_files, report)
        check_app_attest(pkg, manifest, manifest_bytes, args.apple_root, report)
        print()
        print(f"SHA-256 паспорта (manifest.json): {hashlib.sha256(manifest_bytes).hexdigest()}")
        if report.failures:
            print(f"ИТОГ: обнаружены ошибки ({report.failures}). Пакет изменен или поврежден.")
            return 1
        suffix = f", замечаний: {report.warnings}" if report.warnings else ""
        print(f"ИТОГ: нарушений целостности не обнаружено{suffix}.")
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
