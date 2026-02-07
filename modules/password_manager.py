from __future__ import annotations

import base64
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pyotp
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PasswordManagerError(Exception):
    pass


class PasswordManager:
    """
    Serviço: CRUD + encriptação assimétrica (RSA) + 2FA (TOTP).
    Sem input()/print(): a UI fica na main.py.
    """

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        # base_dir = root do projeto
        root = base_dir or Path(__file__).resolve().parent.parent
        self.app_dir = root / "data" / "password_manager"
        self.db_path = self.app_dir / "vault.json"
        self.priv_path = self.app_dir / "rsa_private.pem"
        self.pub_path = self.app_dir / "rsa_public.pem"
        self.totp_path = self.app_dir / "totp_secret.txt"

        self.app_dir.mkdir(parents=True, exist_ok=True)
        self._private_key, self._public_key = self._ensure_rsa_keys()
        self._totp_secret = self._ensure_totp_secret()

    # ---------- public API ----------

    def list_records(self) -> list[dict[str, str]]:
        db = self._load_db()
        # devolve só metadata (sem password)
        return [{"url": r["url"], "user": r["user"], "id": r["id"]} for r in db.get("records", [])]

    def create_record(self, url: str, user: str, password: str) -> None:
        db = self._load_db()
        if self._find_idx(db, url, user) is not None:
            raise PasswordManagerError("Já existe um registo para esse (URL, user).")

        rec = {
            "id": str(uuid.uuid4()),
            "url": url,
            "user": user,
            "enc": self._encrypt({"pass": password}),
        }
        db["records"].append(rec)
        self._save_db(db)

    def update_record(self, url: str, user: Optional[str], new_user: Optional[str], new_password: Optional[str]) -> None:
        db = self._load_db()
        idx = self._find_idx_any(db, url, user)
        if idx is None:
            raise PasswordManagerError("Registo não encontrado.")

        if new_user:
            db["records"][idx]["user"] = new_user
        if new_password:
            db["records"][idx]["enc"] = self._encrypt({"pass": new_password})

        self._save_db(db)

    def delete_record(self, url: str, user: Optional[str]) -> None:
        db = self._load_db()
        idx = self._find_idx_any(db, url, user)
        if idx is None:
            raise PasswordManagerError("Registo não encontrado.")
        db["records"].pop(idx)
        self._save_db(db)

    def consult_password(self, url: str, user: Optional[str], totp_code: str) -> dict[str, str]:
        # 2FA obrigatório
        if not self._verify_totp(totp_code):
            raise PasswordManagerError("2FA inválido.")

        db = self._load_db()
        idx = self._find_idx_any(db, url, user)
        if idx is None:
            raise PasswordManagerError("Registo não encontrado.")

        rec = db["records"][idx]
        try:
            payload = self._decrypt(rec["enc"])
        except Exception as e:
            raise PasswordManagerError("Falha a desencriptar (keys/db corrompidos?).") from e

        return {"url": rec["url"], "user": rec["user"], "pass": payload.get("pass", "")}

    def get_totp_setup_info(self) -> dict[str, str]:
        """
        Para a UI mostrar uma vez (ou sempre, se quiseres):
        - secret
        - provisioning uri (p/ apps que aceitem)
        """
        issuer = "Projeto-LPD"
        account = "password-manager"
        uri = pyotp.TOTP(self._totp_secret).provisioning_uri(name=account, issuer_name=issuer)
        return {"secret": self._totp_secret, "uri": uri}

    # ---------- internals: db ----------

    def _load_db(self) -> Dict[str, Any]:
        if not self.db_path.exists():
            return {"records": []}
        try:
            return json.loads(self.db_path.read_text(encoding="utf-8"))
        except Exception:
            return {"records": []}

    def _save_db(self, db: Dict[str, Any]) -> None:
        self.db_path.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
        self._chmod_600(self.db_path)

    def _find_idx(self, db: Dict[str, Any], url: str, user: str) -> Optional[int]:
        url_norm = url.strip().lower()
        for i, r in enumerate(db.get("records", [])):
            if r.get("url", "").strip().lower() == url_norm and r.get("user") == user:
                return i
        return None

    def _find_idx_any(self, db: Dict[str, Any], url: str, user: Optional[str]) -> Optional[int]:
        url_norm = url.strip().lower()
        for i, r in enumerate(db.get("records", [])):
            if r.get("url", "").strip().lower() == url_norm:
                if user is None or r.get("user") == user:
                    return i
        return None

    # ---------- internals: 2FA ----------

    def _ensure_totp_secret(self) -> str:
        if self.totp_path.exists():
            return self.totp_path.read_text(encoding="utf-8").strip()

        secret = pyotp.random_base32()
        self.totp_path.write_text(secret, encoding="utf-8")
        self._chmod_600(self.totp_path)
        return secret

    def _verify_totp(self, code: str) -> bool:
        return pyotp.TOTP(self._totp_secret).verify(code.strip(), valid_window=1)

    # ---------- internals: crypto ----------

    def _ensure_rsa_keys(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        if self.priv_path.exists() and self.pub_path.exists():
            private_key = serialization.load_pem_private_key(self.priv_path.read_bytes(), password=None)
            public_key = serialization.load_pem_public_key(self.pub_path.read_bytes())
            return private_key, public_key

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        self.priv_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.pub_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        self._chmod_600(self.priv_path)
        self._chmod_600(self.pub_path)
        return private_key, public_key

    def _encrypt(self, payload: Dict[str, Any]) -> Dict[str, str]:
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)

        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

        enc_key = self._public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return {"nonce": self._b64e(nonce), "ciphertext": self._b64e(ciphertext), "enc_key": self._b64e(enc_key)}

    def _decrypt(self, enc: Dict[str, str]) -> Dict[str, Any]:
        aes_key = self._private_key.decrypt(
            self._b64d(enc["enc_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(self._b64d(enc["nonce"]), self._b64d(enc["ciphertext"]), associated_data=None)
        return json.loads(plaintext.decode("utf-8"))

    # ---------- internals: helpers ----------

    def _chmod_600(self, path: Path) -> None:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def _b64e(self, raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("utf-8")

    def _b64d(self, txt: str) -> bytes:
        return base64.urlsafe_b64decode(txt.encode("utf-8"))
