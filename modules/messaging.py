# modules/messaging.py
from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================
# Utils: JSON framing over TCP
# =========================

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket fechado")
        buf += chunk
    return buf

def _send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    header = len(data).to_bytes(4, "big")
    sock.sendall(header + data)

def _recv_json(sock: socket.socket) -> Dict[str, Any]:
    header = _recv_exact(sock, 4)
    n = int.from_bytes(header, "big")
    data = _recv_exact(sock, n)
    return json.loads(data.decode("utf-8"))


# =========================
# Utils: crypto + encoding
# =========================

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _now_iso() -> str:
    # ISO-ish, UTC
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _new_msg_id() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"

def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    """
    Returns (private_pem, public_pem)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub

def load_private_key_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def load_public_key_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)

def rsa_oaep_encrypt(pub_pem: bytes, data: bytes) -> bytes:
    pub = load_public_key_pem(pub_pem)
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_oaep_decrypt(priv_pem: bytes, ct: bytes) -> bytes:
    priv = load_private_key_pem(priv_pem)
    return priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def hybrid_encrypt_for_participants(
    plaintext: bytes,
    participants_pub: Dict[str, bytes],
    aad: Optional[bytes] = None,
) -> Dict[str, Any]:
    """
    AES-GCM encrypt plaintext, then RSA-wrap AES key for each participant.
    Returns dict with nonce/ciphertext and keys per userId (all base64)
    """
    aes_key = os.urandom(32)        # AES-256
    nonce = os.urandom(12)          # recommended for GCM
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)  # ct includes tag internally

    keys: Dict[str, str] = {}
    for uid, pub_pem in participants_pub.items():
        wrapped = rsa_oaep_encrypt(pub_pem, aes_key)
        keys[uid] = _b64e(wrapped)

    return {
        "nonce_b64": _b64e(nonce),
        "ciphertext_b64": _b64e(ct),
        "keys": keys,
    }

def hybrid_decrypt_for_user(
    record: Dict[str, Any],
    user_id: str,
    user_priv_pem: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Given archived record dict, decrypt for a user.
    """
    keys = record.get("keys", {})
    if user_id not in keys:
        raise PermissionError("Não existe chave para este userId neste ficheiro.")
    wrapped_key = _b64d(keys[user_id])
    aes_key = rsa_oaep_decrypt(user_priv_pem, wrapped_key)
    nonce = _b64d(record["nonce_b64"])
    ct = _b64d(record["ciphertext_b64"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, aad)


# =========================
# Server storage layout
# =========================

@dataclass
class StoredMeta:
    msgId: str
    timestamp: str
    from_user: str
    to_user: str
    filename: str
    size: int

def _safe_filename(name: str) -> str:
    # minimal sanitization
    return "".join(c for c in name if c.isalnum() or c in ("-", "_", ".", "@"))

def _conv_key(a: str, b: str) -> str:
    # stable conversation key independent of direction
    x, y = sorted([a, b])
    return f"{_safe_filename(x)}__{_safe_filename(y)}"


# =========================
# MessagingServer
# =========================

class MessagingServer:
    """
    Multi-client TCP server.
    Stores:
      - users.json : { userId: publicKeyPem }
      - messages/<convKey>/msg_<id>.json : encrypted records
      - index.jsonl : one line per message (metadata)
    """
    def __init__(self, host: str, port: int, data_dir: str = "server_data") -> None:
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._lock = threading.Lock()

        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self._messages_dir, exist_ok=True)

        # create users file if missing
        if not os.path.exists(self._users_path):
            with open(self._users_path, "w", encoding="utf-8") as f:
                json.dump({}, f)

        # create index file if missing
        if not os.path.exists(self._index_path):
            open(self._index_path, "a", encoding="utf-8").close()

    @property
    def _users_path(self) -> str:
        return os.path.join(self.data_dir, "users.json")

    @property
    def _messages_dir(self) -> str:
        return os.path.join(self.data_dir, "messages")

    @property
    def _index_path(self) -> str:
        return os.path.join(self.data_dir, "index.jsonl")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def _serve_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_evt.is_set():
            try:
                client_sock, _addr = self._sock.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
            t.start()

    def _handle_client(self, sock: socket.socket) -> None:
        with sock:
            while not self._stop_evt.is_set():
                try:
                    req = _recv_json(sock)
                except Exception:
                    return

                try:
                    op = req.get("op")
                    if op == "register":
                        resp = self._op_register(req)
                    elif op == "send":
                        resp = self._op_send(req)
                    elif op == "list":
                        resp = self._op_list(req)
                    elif op == "get":
                        resp = self._op_get(req)
                    elif op == "delete":
                        resp = self._op_delete(req)
                    elif op == "export":
                        resp = self._op_export(req)
                    else:
                        resp = {"ok": False, "error": "Operação desconhecida"}
                except Exception as e:
                    resp = {"ok": False, "error": str(e)}

                try:
                    _send_json(sock, resp)
                except Exception:
                    return

    # -------- users registry --------

    def _load_users(self) -> Dict[str, str]:
        with open(self._users_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_users(self, users: Dict[str, str]) -> None:
        with open(self._users_path, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)

    def _op_register(self, req: Dict[str, Any]) -> Dict[str, Any]:
        user_id = (req.get("userId") or "").strip()
        pub_pem = (req.get("publicKeyPem") or "").strip()
        if not user_id or not pub_pem:
            return {"ok": False, "error": "userId e publicKeyPem são obrigatórios"}

        with self._lock:
            users = self._load_users()
            # idempotente: se já existe, não falha
            users[user_id] = pub_pem
            self._save_users(users)

        return {"ok": True}

    def _get_pubkey(self, user_id: str) -> bytes:
        users = self._load_users()
        if user_id not in users:
            raise KeyError(f"Utilizador não registado: {user_id}")
        return users[user_id].encode("utf-8")

    # -------- message archive --------

    def _append_index(self, meta: StoredMeta) -> None:
        line = {
            "msgId": meta.msgId,
            "timestamp": meta.timestamp,
            "from": meta.from_user,
            "to": meta.to_user,
            "filename": meta.filename,
            "size": meta.size,
        }
        with open(self._index_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    def _read_index(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not os.path.exists(self._index_path):
            return out
        with open(self._index_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    def _msg_path_for(self, from_user: str, to_user: str, msg_id: str) -> str:
        conv = _conv_key(from_user, to_user)
        conv_dir = os.path.join(self._messages_dir, conv)
        os.makedirs(conv_dir, exist_ok=True)
        return os.path.join(conv_dir, f"msg_{_safe_filename(msg_id)}.json")

    def _op_send(self, req: Dict[str, Any]) -> Dict[str, Any]:
        from_user = (req.get("from") or "").strip()
        to_user = (req.get("to") or "").strip()
        body = req.get("body")
        if not from_user or not to_user or body is None:
            return {"ok": False, "error": "Campos obrigatórios: from, to, body"}

        # carregar pubkeys dos intervenientes
        from_pub = self._get_pubkey(from_user)
        to_pub = self._get_pubkey(to_user)

        msg_id = _new_msg_id()
        ts = _now_iso()

        # AAD opcional (mete metadata para ligar integridade ao envelope)
        aad = f"{msg_id}|{ts}|{from_user}|{to_user}".encode("utf-8")

        payload = {
            "msgId": msg_id,
            "timestamp": ts,
            "from": from_user,
            "to": to_user,
            "body": str(body),
        }
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        enc = hybrid_encrypt_for_participants(
            plaintext=plaintext,
            participants_pub={from_user: from_pub, to_user: to_pub},
            aad=aad,
        )

        record = {
            "id": msg_id,
            "ts": ts,
            "from": from_user,
            "to": to_user,
            "alg": "AES-256-GCM + RSA-OAEP(SHA-256)",
            "aad_b64": _b64e(aad),
            "nonce_b64": enc["nonce_b64"],
            "ciphertext_b64": enc["ciphertext_b64"],
            "keys": enc["keys"],
        }

        path = self._msg_path_for(from_user, to_user, msg_id)
        data = json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)

        meta = StoredMeta(
            msgId=msg_id,
            timestamp=ts,
            from_user=from_user,
            to_user=to_user,
            filename=path,
            size=len(data),
        )
        with self._lock:
            self._append_index(meta)

        return {"ok": True, "msgId": msg_id}

    def _op_list(self, req: Dict[str, Any]) -> Dict[str, Any]:
        user_id = (req.get("userId") or "").strip()
        with_user = (req.get("withUser") or "").strip() or None
        if not user_id:
            return {"ok": False, "error": "userId é obrigatório"}

        idx = self._read_index()
        out: List[Dict[str, Any]] = []
        for m in idx:
            a = m.get("from")
            b = m.get("to")
            if user_id not in (a, b):
                continue
            if with_user and with_user not in (a, b):
                continue

            path = m.get("filename")
            if not path or not os.path.exists(path):
                continue
            
            out.append({
                "msgId": m["msgId"],
                "timestamp": m["timestamp"],
                "from": a,
                "to": b,
                "size": m.get("size", 0),
            })

        # ordena por timestamp (string ISO UTC funciona)
        out.sort(key=lambda x: x["timestamp"])
        return {"ok": True, "messages": out}

    def _find_file_by_msgid(self, msg_id: str) -> Optional[str]:
        idx = self._read_index()
        for m in idx:
            if m.get("msgId") == msg_id:
                return m.get("filename")
        return None

    def _op_get(self, req: Dict[str, Any]) -> Dict[str, Any]:
        user_id = (req.get("userId") or "").strip()
        msg_id = (req.get("msgId") or "").strip()
        if not user_id or not msg_id:
            return {"ok": False, "error": "userId e msgId são obrigatórios"}

        path = self._find_file_by_msgid(msg_id)
        if not path or not os.path.exists(path):
            return {"ok": False, "error": "msgId não encontrado"}

        # autorização: tem de ser interveniente (ver no próprio ficheiro)
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)

        if user_id not in (record.get("from"), record.get("to")):
            return {"ok": False, "error": "Sem permissões para esta mensagem"}

        return {"ok": True, "record": record}

    def _op_delete(self, req: Dict[str, Any]) -> Dict[str, Any]:
        user_id = (req.get("userId") or "").strip()
        msg_ids = req.get("msgIds")
        if not user_id or not isinstance(msg_ids, list):
            return {"ok": False, "error": "userId e msgIds(list) são obrigatórios"}

        deleted: List[str] = []
        for msg_id in msg_ids:
            msg_id = str(msg_id).strip()
            if not msg_id:
                continue
            path = self._find_file_by_msgid(msg_id)
            if not path or not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    record = json.load(f)
                if user_id not in (record.get("from"), record.get("to")):
                    continue
                os.remove(path)
                deleted.append(msg_id)
            except Exception:
                continue

        # Nota: index.jsonl fica com linhas antigas; para projeto académico isto é aceitável.
        # Se quiseres “limpo”, faz rebuild do index.
        return {"ok": True, "deleted": deleted}

    def _op_export(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exporta todas as mensagens em que userId é interveniente
        para um blob encriptado "para ele" (RSA wrap + AESGCM).
        Retorna um JSON record para o cliente gravar em ficheiro.
        """
        user_id = (req.get("userId") or "").strip()
        if not user_id:
            return {"ok": False, "error": "userId é obrigatório"}

        # recolhe records (encriptados) — export “bruto”
        idx = self._read_index()
        records: List[Dict[str, Any]] = []
        for m in idx:
            if user_id not in (m.get("from"), m.get("to")):
                continue
            path = m.get("filename")
            if not path or not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    records.append(json.load(f))
            except Exception:
                continue

        export_plain = json.dumps(
            {
                "exportedAt": _now_iso(),
                "userId": user_id,
                "count": len(records),
                "records": records,
            },
            ensure_ascii=False,
            indent=2
        ).encode("utf-8")

        user_pub = self._get_pubkey(user_id)
        export_id = f"export-{_new_msg_id()}"
        aad = f"{export_id}|{user_id}".encode("utf-8")

        enc = hybrid_encrypt_for_participants(
            plaintext=export_plain,
            participants_pub={user_id: user_pub},
            aad=aad,
        )

        backup_record = {
            "type": "secure_backup_v1",
            "exportId": export_id,
            "userId": user_id,
            "alg": "AES-256-GCM + RSA-OAEP(SHA-256)",
            "aad_b64": _b64e(aad),
            "nonce_b64": enc["nonce_b64"],
            "ciphertext_b64": enc["ciphertext_b64"],
            "keys": enc["keys"],  # only userId exists here
        }

        return {"ok": True, "backup": backup_record}


# =========================
# MessagingClient
# =========================

class MessagingClient:
    def __init__(self, user_id: str, host: str, port: int, key_dir: str = "client_keys") -> None:
        self.user_id = user_id
        self.host = host
        self.port = port
        self.key_dir = key_dir
        self._sock: Optional[socket.socket] = None

        os.makedirs(self.key_dir, exist_ok=True)
        self._ensure_keys()

    @property
    def _priv_path(self) -> str:
        return os.path.join(self.key_dir, f"{_safe_filename(self.user_id)}_private.pem")

    @property
    def _pub_path(self) -> str:
        return os.path.join(self.key_dir, f"{_safe_filename(self.user_id)}_public.pem")

    def _ensure_keys(self) -> None:
        if os.path.exists(self._priv_path) and os.path.exists(self._pub_path):
            return
        priv, pub = generate_rsa_keypair()
        with open(self._priv_path, "wb") as f:
            f.write(priv)
        with open(self._pub_path, "wb") as f:
            f.write(pub)

    def _load_priv(self) -> bytes:
        with open(self._priv_path, "rb") as f:
            return f.read()

    def _load_pub(self) -> bytes:
        with open(self._pub_path, "rb") as f:
            return f.read()

    def connect(self) -> None:
        if self._sock:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        self._sock = s

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        finally:
            self._sock = None

    def _rpc(self, req: Dict[str, Any]) -> Dict[str, Any]:
        if not self._sock:
            raise ConnectionError("Cliente não está ligado ao servidor.")
        _send_json(self._sock, req)
        resp = _recv_json(self._sock)
        if not resp.get("ok", False):
            raise RuntimeError(resp.get("error", "Erro desconhecido"))
        return resp

    def register(self) -> None:
        pub_pem = self._load_pub().decode("utf-8")
        self._rpc({"op": "register", "userId": self.user_id, "publicKeyPem": pub_pem})

    def send_message(self, to: str, body: str) -> Dict[str, Any]:
        resp = self._rpc({"op": "send", "from": self.user_id, "to": to, "body": body})
        return {"msgId": resp.get("msgId")}

    def list_messages(self, with_user: Optional[str] = None) -> List[Dict[str, Any]]:
        resp = self._rpc({"op": "list", "userId": self.user_id, "withUser": with_user})
        return resp.get("messages", [])

    def download_messages(self, msg_ids: List[str], out_dir: str) -> List[str]:
        os.makedirs(out_dir, exist_ok=True)
        saved: List[str] = []
        for mid in msg_ids:
            resp = self._rpc({"op": "get", "userId": self.user_id, "msgId": mid})
            record = resp["record"]
            path = os.path.join(out_dir, f"msg_{_safe_filename(mid)}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
            saved.append(path)
        return saved

    def delete_messages(self, msg_ids: List[str]) -> None:
        self._rpc({"op": "delete", "userId": self.user_id, "msgIds": msg_ids})

    def export_messages(self, out_file: str) -> None:
        resp = self._rpc({"op": "export", "userId": self.user_id})
        backup = resp["backup"]
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(backup, f, ensure_ascii=False, indent=2)

    def decrypt_archived_message_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)
        aad = _b64d(record["aad_b64"]) if "aad_b64" in record else None
        plain = hybrid_decrypt_for_user(
            record=record,
            user_id=self.user_id,
            user_priv_pem=self._load_priv(),
            aad=aad,
        )
        # plain is JSON with {msgId,timestamp,from,to,body}
        return plain.decode("utf-8")

    def decrypt_backup_file(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as f:
            record = json.load(f)
        aad = _b64d(record["aad_b64"]) if "aad_b64" in record else None
        plain = hybrid_decrypt_for_user(
            record=record,
            user_id=self.user_id,
            user_priv_pem=self._load_priv(),
            aad=aad,
        )
        return plain.decode("utf-8")
