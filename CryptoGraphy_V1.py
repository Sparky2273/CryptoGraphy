"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CryptoGraphy v1.0.0  —  Advanced File Encryption Suite                       ║
║  Single-file PyQt6 application                                               ║
║                                                                              ║
║  v1:                                                                  ║
║   • Light / Dark theme toggle in header                                      ║
║   • Per-file progress bar (individual file %, not just overall)              ║
║   • Delete-selected items from file list (not just "Clear All")              ║
║   • File-based logging with timestamp (enable via checkbox)                  ║
║   • Activity indicator ("Encrypting…", "Decrypting…", "Loading…")           ║
║   • AES-256-GCM algorithm option with auto-detection on decrypt              ║
║   • Algorithm recommendation tooltips                                        ║
║   • Layout fixed — all controls visible in standard window (no max needed)  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import stat
import json
import uuid
import base64
import random
import string
import hashlib
import logging
import platform
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable, Dict, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod
from enum import Enum

# ── Crypto imports ─────────────────────────────────────────────────────────────
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-256-GCM

# ── PyQt6 imports ──────────────────────────────────────────────────────────────
from PyQt6.QtGui import (
    QFont,
    QIcon,
    QColor,
    QPalette,
    QPainter,
    QLinearGradient,
    QPen,
    QBrush,
    QCursor,
)
from PyQt6.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QDateTime,
    QTimer,
    QPoint,
    QRect,
    QSize,
    QObject,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QPushButton,
    QLineEdit,
    QLabel,
    QFileDialog,
    QProgressBar,
    QMessageBox,
    QFrame,
    QRadioButton,
    QCheckBox,
    QTabWidget,
    QTextEdit,
    QComboBox,
    QGroupBox,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QSizePolicy,
    QSpacerItem,
    QButtonGroup,
    QToolButton,
    QListWidget,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QSlider,
    QSpinBox,
)

# ══════════════════════════════════════════════════════════════════════════════
#  PLATFORM HELPERS
# ══════════════════════════════════════════════════════════════════════════════

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    try:
        import win32con, win32api

        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
else:
    HAS_WIN32 = False


def get_file_attributes(path: Path) -> Tuple[bool, int]:
    if IS_WINDOWS and HAS_WIN32:
        try:
            attrs = win32api.GetFileAttributes(str(path))
            return bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN), attrs
        except Exception:
            pass
    return path.name.startswith("."), 0


def set_file_attributes(path: Path, attributes: int) -> None:
    if IS_WINDOWS and HAS_WIN32:
        try:
            win32api.SetFileAttributes(str(path), attributes)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════


class CryptoException(Exception):
    pass


class InvalidKeyException(CryptoException):
    pass


class FileAccessException(CryptoException):
    pass


# ══════════════════════════════════════════════════════════════════════════════
#  ENUMS
# ══════════════════════════════════════════════════════════════════════════════


class AlgorithmType(Enum):
    """
    v1: Supported encryption algorithms.
    FERNET   — AES-128-CBC + HMAC-SHA256 (default, recommended, fully self-contained).
    AES_GCM  — AES-256-GCM (authenticated encryption, slightly faster on modern CPUs).
    The application auto-detects which algorithm was used when decrypting.
    """

    FERNET = "Fernet (AES-128-CBC + HMAC-SHA256) ★ Recommended"
    AES_GCM = "AES-256-GCM (Authenticated Encryption)"


# Magic prefix written at the start of every AES-GCM ciphertext so we can
# auto-detect the algorithm during decryption without user intervention.
_MAGIC_AESGCM = b"CGAE"  # CryptoGraphy AES-GCM Encrypted


class NameMode(Enum):
    KEEP_ORIGINAL = "Keep original name"
    RANDOM_NAME = "Random name (keep extension)"
    RANDOM_NAME_NO_EXT = "Random name (no extension)"
    ENCRYPT_NAME = "Encrypt filename"
    CUSTOM_PREFIX = "Custom prefix + random"


class ExtMode(Enum):
    KEEP_ORIGINAL = "Keep original extension"
    SPOOF_TEXT = "Spoof as text format"
    SPOOF_CODE = "Spoof as code format"
    SPOOF_DATA = "Spoof as data format"
    SPOOF_MEDIA = "Spoof as media format"
    CUSTOM_EXT = "Custom extension"
    NO_EXTENSION = "No extension"


TEXT_EXTENSIONS = [".txt", ".md", ".rst", ".log", ".csv", ".tsv"]
CODE_EXTENSIONS = [
    ".py",
    ".js",
    ".ts",
    ".java",
    ".cpp",
    ".c",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
]
DATA_EXTENSIONS = [".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"]
MEDIA_EXTENSIONS = [".jpg", ".png", ".mp3", ".mp4", ".wav", ".gif", ".bmp", ".webp"]
ALL_SPOOF_EXTENSIONS = (
    TEXT_EXTENSIONS + CODE_EXTENSIONS + DATA_EXTENSIONS + MEDIA_EXTENSIONS
)


# ══════════════════════════════════════════════════════════════════════════════
#  KEY MANAGER
# ══════════════════════════════════════════════════════════════════════════════


class KeyManager:
    SALT = b"\xc9\x8f\xa7\xc3\xad\xf8\xdd\xe9\xf1\x8e\xfd\x07\xc8\xc4\x8d\xc6"
    ITERATIONS = 100_000

    @classmethod
    def generate_key(cls, password: str) -> bytes:
        """Derive a URL-safe base64-encoded 32-byte key from a password."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=cls.SALT,
                iterations=cls.ITERATIONS,
            )
            return base64.urlsafe_b64encode(kdf.derive(password.encode()))
        except Exception as e:
            raise CryptoException(f"Key generation failed: {e}")

    @staticmethod
    def generate_random_key() -> bytes:
        return Fernet.generate_key()

    @staticmethod
    def key_strength(password: str) -> int:
        score = 0
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 15
        if any(c.isupper() for c in password):
            score += 12
        if any(c.islower() for c in password):
            score += 12
        if any(c.isdigit() for c in password):
            score += 13
        if any(c in string.punctuation for c in password):
            score += 13
        return min(score, 100)


# ══════════════════════════════════════════════════════════════════════════════
#  FILENAME TRANSFORM
# ══════════════════════════════════════════════════════════════════════════════


class FilenameTransformer:
    @staticmethod
    def _random_stem(length: int = 16) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    @staticmethod
    def _encrypt_stem(name: str, key: bytes) -> str:
        return hashlib.blake2b(name.encode(), key=key[:32], digest_size=16).hexdigest()

    @classmethod
    def transform(
        cls,
        original_path: Path,
        name_mode: NameMode,
        ext_mode: ExtMode,
        key: bytes,
        custom_prefix: str = "",
        custom_ext: str = "",
        spoof_ext_override: str = "",
    ) -> Tuple[str, str]:
        stem = original_path.stem
        suffix = original_path.suffix.lower()

        if name_mode == NameMode.KEEP_ORIGINAL:
            new_stem = stem
        elif name_mode == NameMode.RANDOM_NAME:
            new_stem = cls._random_stem()
        elif name_mode == NameMode.RANDOM_NAME_NO_EXT:
            new_stem = cls._random_stem()
            suffix = ""
        elif name_mode == NameMode.ENCRYPT_NAME:
            new_stem = cls._encrypt_stem(stem, key)
        elif name_mode == NameMode.CUSTOM_PREFIX:
            new_stem = (custom_prefix or "file_") + cls._random_stem(8)
        else:
            new_stem = stem

        if ext_mode == ExtMode.KEEP_ORIGINAL:
            new_suffix = suffix
        elif ext_mode == ExtMode.NO_EXTENSION:
            new_suffix = ""
        elif ext_mode == ExtMode.CUSTOM_EXT:
            ext = custom_ext.strip()
            new_suffix = ext if ext.startswith(".") else f".{ext}"
        elif ext_mode == ExtMode.SPOOF_TEXT:
            new_suffix = spoof_ext_override or random.choice(TEXT_EXTENSIONS)
        elif ext_mode == ExtMode.SPOOF_CODE:
            new_suffix = spoof_ext_override or random.choice(CODE_EXTENSIONS)
        elif ext_mode == ExtMode.SPOOF_DATA:
            new_suffix = spoof_ext_override or random.choice(DATA_EXTENSIONS)
        elif ext_mode == ExtMode.SPOOF_MEDIA:
            new_suffix = spoof_ext_override or random.choice(MEDIA_EXTENSIONS)
        else:
            new_suffix = suffix

        return new_stem + new_suffix, original_path.name


# ══════════════════════════════════════════════════════════════════════════════
#  MANIFEST
# ══════════════════════════════════════════════════════════════════════════════


class Manifest:
    FILENAME = ".cg_manifest.json"

    def __init__(self, directory: Path):
        self.path = directory / self.FILENAME
        self.entries: Dict[str, str] = {}
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    self.entries = json.load(f)
            except Exception:
                self.entries = {}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.entries, f, indent=2)

    def add(self, new_name: str, original_name: str):
        self.entries[new_name] = original_name

    def get_original(self, new_name: str) -> Optional[str]:
        return self.entries.get(new_name)

    def remove(self, name: str):
        self.entries.pop(name, None)


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════


class CryptoOperation(ABC):
    @abstractmethod
    def process(self, data: bytes) -> bytes:
        pass


class FernetEncryptOperation(CryptoOperation):
    """Original Fernet (AES-128-CBC + HMAC-SHA256). Recommended default."""

    def __init__(self, key: bytes):
        self.fernet = Fernet(key)

    def process(self, data: bytes) -> bytes:
        try:
            return self.fernet.encrypt(data)
        except Exception as e:
            raise CryptoException(f"Fernet encryption failed: {e}")


class FernetDecryptOperation(CryptoOperation):
    def __init__(self, key: bytes):
        self.fernet = Fernet(key)

    def process(self, data: bytes) -> bytes:
        try:
            return self.fernet.decrypt(data)
        except InvalidToken:
            raise InvalidKeyException("Invalid decryption key (Fernet)")
        except Exception as e:
            raise CryptoException(f"Fernet decryption failed: {e}")


class AESGCMEncryptOperation(CryptoOperation):
    """
    v1 — AES-256-GCM authenticated encryption.
    Output format: [4-byte magic][12-byte nonce][ciphertext+16-byte GCM tag]
    The magic prefix allows auto-detection during decryption.
    """

    MAGIC = _MAGIC_AESGCM

    def __init__(self, key: bytes):
        # key is URL-safe base64 of 32 bytes from PBKDF2
        raw = base64.urlsafe_b64decode(key)[:32]
        self.aesgcm = AESGCM(raw)

    def process(self, data: bytes) -> bytes:
        try:
            nonce = os.urandom(12)  # 96-bit random nonce
            ct = self.aesgcm.encrypt(nonce, data, None)  # includes 16-byte tag
            return self.MAGIC + nonce + ct
        except Exception as e:
            raise CryptoException(f"AES-GCM encryption failed: {e}")


class AESGCMDecryptOperation(CryptoOperation):
    """
    v1 — AES-256-GCM decryption.
    Expects data produced by AESGCMEncryptOperation.
    """

    MAGIC = _MAGIC_AESGCM

    def __init__(self, key: bytes):
        raw = base64.urlsafe_b64decode(key)[:32]
        self.aesgcm = AESGCM(raw)

    def process(self, data: bytes) -> bytes:
        if data[:4] != self.MAGIC:
            raise CryptoException("Not an AES-GCM encrypted file (magic mismatch)")
        nonce = data[4:16]
        ct = data[16:]
        try:
            return self.aesgcm.decrypt(nonce, ct, None)
        except Exception:
            raise InvalidKeyException("Invalid decryption key (AES-256-GCM)")


def detect_algorithm(data: bytes) -> AlgorithmType:
    """
    v1 — Inspect the first bytes of an encrypted blob to determine
    which algorithm was used.  Called automatically before decryption so the
    user does not need to remember which algorithm they chose.
    """
    if data[:4] == _MAGIC_AESGCM:
        return AlgorithmType.AES_GCM
    return AlgorithmType.FERNET


# ══════════════════════════════════════════════════════════════════════════════
#  SELF-EXCLUSION LIST
# ══════════════════════════════════════════════════════════════════════════════

EXCLUDED_NAMES = {
    "cryptography.py",
    "cryptography.exe",
    "crypto-graphy.py",
    "crypto-graphy.exe",
    "crypto_graphy.py",
    "crypto_graphy.exe",
    "CryptoGraphy.py",
    "CryptoGraphy.exe",
    "CryptoGraphy_V1.py",
    "cryptography.log",
    Manifest.FILENAME,
}


# ══════════════════════════════════════════════════════════════════════════════
#  FILE PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class ProcessResult:
    original_path: Path
    new_path: Optional[Path] = None
    success: bool = True
    error: str = ""


def name_change_required(name_mode: NameMode, ext_mode: ExtMode) -> bool:
    return name_mode != NameMode.KEEP_ORIGINAL or ext_mode != ExtMode.KEEP_ORIGINAL


class FileProcessor:
    """Handles actual file read / encrypt|decrypt / rename / write cycle."""

    def __init__(
        self,
        encrypt: bool,
        key: bytes,
        algorithm: AlgorithmType = AlgorithmType.FERNET,
        name_mode: NameMode = NameMode.KEEP_ORIGINAL,
        ext_mode: ExtMode = ExtMode.KEEP_ORIGINAL,
        custom_prefix: str = "",
        custom_ext: str = "",
        spoof_ext_override: str = "",
        use_manifest: bool = True,
    ):
        self.encrypt = encrypt
        self.key = key
        self.algorithm = algorithm
        self.name_mode = name_mode
        self.ext_mode = ext_mode
        self.custom_prefix = custom_prefix
        self.custom_ext = custom_ext
        self.spoof_ext_override = spoof_ext_override
        self.use_manifest = use_manifest
        self.logger = logging.getLogger(__name__)

    def _make_operation(self, data: bytes) -> CryptoOperation:
        """
        Return the correct CryptoOperation.
        During decryption the algorithm is auto-detected from `data` bytes.
        During encryption the user-chosen algorithm is used.
        """
        if self.encrypt:
            if self.algorithm == AlgorithmType.AES_GCM:
                return AESGCMEncryptOperation(self.key)
            return FernetEncryptOperation(self.key)
        else:
            # Auto-detect regardless of what the user chose
            detected = detect_algorithm(data)
            if detected == AlgorithmType.AES_GCM:
                return AESGCMDecryptOperation(self.key)
            return FernetDecryptOperation(self.key)

    def process_file(
        self, path: Path, manifest: Optional[Manifest] = None
    ) -> ProcessResult:
        result = ProcessResult(original_path=path)
        try:
            is_hidden, orig_attrs = get_file_attributes(path)

            try:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

            if is_hidden and IS_WINDOWS and HAS_WIN32:
                try:
                    win32api.SetFileAttributes(
                        str(path), win32con.FILE_ATTRIBUTE_NORMAL
                    )
                except Exception:
                    pass

            with open(path, "rb") as f:
                data = f.read()

            operation = self._make_operation(data)
            processed = operation.process(data)

            if self.encrypt:
                new_name, orig_name = FilenameTransformer.transform(
                    path,
                    self.name_mode,
                    self.ext_mode,
                    self.key,
                    self.custom_prefix,
                    self.custom_ext,
                    self.spoof_ext_override,
                )
            else:
                new_name = path.name
                orig_name = path.name
                if manifest:
                    restored = manifest.get_original(path.name)
                    if restored:
                        new_name = restored

            new_path = path.parent / new_name

            with open(path, "wb") as f:
                f.write(processed)

            if new_path != path:
                if new_path.exists() and new_path != path:
                    new_path = path.parent / (
                        new_path.stem + "_" + uuid.uuid4().hex[:4] + new_path.suffix
                    )
                path.rename(new_path)

            if is_hidden and IS_WINDOWS and HAS_WIN32:
                try:
                    win32api.SetFileAttributes(str(new_path), orig_attrs)
                except Exception:
                    pass

            if manifest and self.use_manifest:
                if self.encrypt:
                    manifest.add(new_name, orig_name)
                else:
                    manifest.remove(path.name)
                manifest.save()

            result.new_path = new_path
            result.success = True

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"Error processing {path}: {e}")

        return result


# ══════════════════════════════════════════════════════════════════════════════
#  DIRECTORY CRYPTO  (orchestrator)
# ══════════════════════════════════════════════════════════════════════════════


class DirectoryCrypto:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _make_processor(
        self,
        password: str,
        encrypt: bool,
        algorithm: AlgorithmType,
        name_mode,
        ext_mode,
        custom_prefix,
        custom_ext,
        spoof_ext_override,
        use_manifest: bool = True,
    ) -> FileProcessor:
        key = KeyManager.generate_key(password)
        return FileProcessor(
            encrypt=encrypt,
            key=key,
            algorithm=algorithm,
            name_mode=name_mode,
            ext_mode=ext_mode,
            custom_prefix=custom_prefix,
            custom_ext=custom_ext,
            spoof_ext_override=spoof_ext_override,
            use_manifest=use_manifest,
        )

    def get_files(self, directory: Path) -> List[Path]:
        return [
            f
            for f in directory.iterdir()
            if f.is_file() and f.name not in EXCLUDED_NAMES
        ]

    def process_single_file(
        self,
        file_path: Path,
        password: str,
        encrypt: bool = True,
        algorithm: AlgorithmType = AlgorithmType.FERNET,
        name_mode: NameMode = NameMode.KEEP_ORIGINAL,
        ext_mode: ExtMode = ExtMode.KEEP_ORIGINAL,
        custom_prefix: str = "",
        custom_ext: str = "",
        spoof_ext_override: str = "",
        use_manifest: bool = True,
    ) -> ProcessResult:
        processor = self._make_processor(
            password,
            encrypt,
            algorithm,
            name_mode,
            ext_mode,
            custom_prefix,
            custom_ext,
            spoof_ext_override,
            use_manifest,
        )
        manifest = Manifest(file_path.parent) if use_manifest else None
        return processor.process_file(file_path, manifest)

    def process_directory(
        self,
        directory: Path,
        password: str,
        encrypt: bool = True,
        algorithm: AlgorithmType = AlgorithmType.FERNET,
        name_mode: NameMode = NameMode.KEEP_ORIGINAL,
        ext_mode: ExtMode = ExtMode.KEEP_ORIGINAL,
        custom_prefix: str = "",
        custom_ext: str = "",
        spoof_ext_override: str = "",
        use_manifest: bool = True,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[ProcessResult]:
        """progress_callback(current_file_index, total_files, filename)"""
        processor = self._make_processor(
            password,
            encrypt,
            algorithm,
            name_mode,
            ext_mode,
            custom_prefix,
            custom_ext,
            spoof_ext_override,
            use_manifest,
        )
        manifest = Manifest(directory) if use_manifest else None
        files = self.get_files(directory)
        results = []
        total = len(files)

        for i, f in enumerate(files, 1):
            r = processor.process_file(f, manifest)
            results.append(r)
            if progress_callback:
                name = r.new_path.name if r.new_path else f.name
                progress_callback(i, total, name)

        return results


# ══════════════════════════════════════════════════════════════════════════════
#  THEME MANAGER  (v1)
# ══════════════════════════════════════════════════════════════════════════════


class ThemeManager:
    """
    Manages light and dark themes.  Call ThemeManager.apply(app, 'dark'|'light').
    The current theme name is stored in ThemeManager.current.
    """

    current: str = "dark"

    # ─── Dark palette (v1) ─────────────────────────────────
    DARK = """
QMainWindow, QWidget {
    background-color: #0D0F14; color: #E8EAFF;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
}
QScrollBar:vertical { background: #131720; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #2A3050; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #00E5FF; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #131720; height: 8px; border-radius: 4px; }
QScrollBar::handle:horizontal { background: #2A3050; border-radius: 4px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #00E5FF; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

QPushButton {
    background-color: #1E2436; color: #E8EAFF;
    border: 1px solid #2A3050; padding: 7px 16px;
    border-radius: 6px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background-color: #2A3050; border-color: #00E5FF; color: #00E5FF; }
QPushButton:pressed { background-color: #00E5FF; color: #0D0F14; }
QPushButton:disabled { background-color: #131720; color: #2A3050; border-color: #1A1F2E; }
QPushButton#accent {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00E5FF, stop:1 #7B61FF);
    color: #0D0F14; border: none; font-size: 13px; font-weight: 700; padding: 10px 24px;
}
QPushButton#accent:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #33EEFF, stop:1 #9B81FF);
    color: #0D0F14;
}
QPushButton#danger { background-color: transparent; color: #FF3860; border: 1px solid #FF3860; }
QPushButton#danger:hover { background-color: #FF3860; color: #fff; }

QLineEdit, QTextEdit {
    background-color: #131720; color: #E8EAFF;
    border: 1px solid #2A3050; border-radius: 6px;
    padding: 6px 10px; font-size: 12px;
    selection-background-color: #00E5FF; selection-color: #0D0F14;
}
QLineEdit:focus, QTextEdit:focus { border-color: #00E5FF; background-color: #161B2A; }

QComboBox {
    background-color: #131720; color: #E8EAFF;
    border: 1px solid #2A3050; border-radius: 6px; padding: 5px 10px; font-size: 12px;
}
QComboBox:hover { border-color: #00E5FF; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: right center; width: 24px; border: none; }
QComboBox::down-arrow { border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid #00E5FF; margin-right: 6px; }
QComboBox QAbstractItemView {
    background-color: #1A1F2E; color: #E8EAFF;
    border: 1px solid #2A3050;
    selection-background-color: #2A3050; selection-color: #00E5FF; outline: none;
}

QProgressBar {
    background-color: #131720; border: 1px solid #2A3050; border-radius: 6px;
    text-align: center; color: #E8EAFF; font-size: 11px; height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00E5FF, stop:1 #7B61FF);
    border-radius: 5px;
}

QTabWidget::pane { border: 1px solid #2A3050; border-radius: 6px; top: -1px; background-color: #131720; }
QTabBar::tab {
    background-color: #0D0F14; color: #6B7299; padding: 8px 18px;
    border: 1px solid #1A1F2E; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
    font-size: 12px; font-weight: 600; margin-right: 2px;
}
QTabBar::tab:selected { background-color: #131720; color: #00E5FF; border-color: #2A3050; border-bottom: 2px solid #00E5FF; }
QTabBar::tab:hover:!selected { background-color: #1A1F2E; color: #E8EAFF; }

QGroupBox {
    border: 1px solid #2A3050; border-radius: 6px; margin-top: 10px; padding-top: 6px;
    font-size: 11px; font-weight: 700; color: #6B7299; letter-spacing: 1px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; background-color: #0D0F14; padding: 0 4px; color: #00E5FF; }

QCheckBox, QRadioButton { color: #E8EAFF; spacing: 8px; font-size: 12px; }
QCheckBox::indicator, QRadioButton::indicator { width: 15px; height: 15px; border: 1px solid #2A3050; border-radius: 3px; background: #131720; }
QCheckBox::indicator:checked { background: #00E5FF; border-color: #00E5FF; }
QRadioButton::indicator { border-radius: 8px; }
QRadioButton::indicator:checked { background: #7B61FF; border-color: #7B61FF; }

QListWidget {
    background-color: #131720; color: #E8EAFF;
    border: 1px solid #2A3050; border-radius: 6px; outline: none; font-size: 12px;
}
QListWidget::item { padding: 5px 10px; }
QListWidget::item:selected { background-color: #1E2436; color: #00E5FF; }
QListWidget::item:hover { background-color: #1A1F2E; }

QSlider::groove:horizontal { background: #1A1F2E; height: 4px; border-radius: 2px; }
QSlider::handle:horizontal { background: #00E5FF; width: 14px; height: 14px; margin: -5px 0; border-radius: 7px; }
QSlider::sub-page:horizontal { background: #00E5FF; border-radius: 2px; }
"""

    # ─── Light palette (v1) ─────────────────────────────────────────────
    LIGHT = """
QMainWindow, QWidget {
    background-color: #F0F2F8; color: #1A1E2E;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
}
QScrollBar:vertical { background: #E0E3EE; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #B0B8D8; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #0088BB; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #E0E3EE; height: 8px; border-radius: 4px; }
QScrollBar::handle:horizontal { background: #B0B8D8; border-radius: 4px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #0088BB; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

QPushButton {
    background-color: #FFFFFF; color: #1A1E2E;
    border: 1px solid #C8CEDF; padding: 7px 16px;
    border-radius: 6px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background-color: #E8ECFA; border-color: #0088BB; color: #0088BB; }
QPushButton:pressed { background-color: #0088BB; color: #FFFFFF; }
QPushButton:disabled { background-color: #E8EAF0; color: #B0B8C8; border-color: #D0D5E0; }
QPushButton#accent {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0099CC, stop:1 #6B4FCC);
    color: #FFFFFF; border: none; font-size: 13px; font-weight: 700; padding: 10px 24px;
}
QPushButton#accent:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00AADD, stop:1 #7B5FDD);
}
QPushButton#danger { background-color: transparent; color: #C02040; border: 1px solid #C02040; }
QPushButton#danger:hover { background-color: #C02040; color: #fff; }

QLineEdit, QTextEdit {
    background-color: #FFFFFF; color: #1A1E2E;
    border: 1px solid #C8CEDF; border-radius: 6px;
    padding: 6px 10px; font-size: 12px;
    selection-background-color: #0099CC; selection-color: #FFFFFF;
}
QLineEdit:focus, QTextEdit:focus { border-color: #0099CC; background-color: #F8F9FF; }

QComboBox {
    background-color: #FFFFFF; color: #1A1E2E;
    border: 1px solid #C8CEDF; border-radius: 6px; padding: 5px 10px; font-size: 12px;
}
QComboBox:hover { border-color: #0099CC; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: right center; width: 24px; border: none; }
QComboBox::down-arrow { border-left: 4px solid transparent; border-right: 4px solid transparent; border-top: 5px solid #0099CC; margin-right: 6px; }
QComboBox QAbstractItemView {
    background-color: #FFFFFF; color: #1A1E2E;
    border: 1px solid #C8CEDF;
    selection-background-color: #E0E8F8; selection-color: #0099CC; outline: none;
}

QProgressBar {
    background-color: #E0E3EE; border: 1px solid #C8CEDF; border-radius: 6px;
    text-align: center; color: #1A1E2E; font-size: 11px; height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #0099CC, stop:1 #6B4FCC);
    border-radius: 5px;
}

QTabWidget::pane { border: 1px solid #C8CEDF; border-radius: 6px; top: -1px; background-color: #FFFFFF; }
QTabBar::tab {
    background-color: #E8EAEE; color: #6B7299; padding: 8px 18px;
    border: 1px solid #C8CEDF; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
    font-size: 12px; font-weight: 600; margin-right: 2px;
}
QTabBar::tab:selected { background-color: #FFFFFF; color: #0099CC; border-color: #C8CEDF; border-bottom: 2px solid #0099CC; }
QTabBar::tab:hover:!selected { background-color: #F0F2F8; color: #1A1E2E; }

QGroupBox {
    border: 1px solid #C8CEDF; border-radius: 6px; margin-top: 10px; padding-top: 6px;
    font-size: 11px; font-weight: 700; color: #6B7299; letter-spacing: 1px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; background-color: #F0F2F8; padding: 0 4px; color: #0099CC; }

QCheckBox, QRadioButton { color: #1A1E2E; spacing: 8px; font-size: 12px; }
QCheckBox::indicator, QRadioButton::indicator { width: 15px; height: 15px; border: 1px solid #C8CEDF; border-radius: 3px; background: #FFFFFF; }
QCheckBox::indicator:checked { background: #0099CC; border-color: #0099CC; }
QRadioButton::indicator { border-radius: 8px; }
QRadioButton::indicator:checked { background: #6B4FCC; border-color: #6B4FCC; }

QListWidget {
    background-color: #FFFFFF; color: #1A1E2E;
    border: 1px solid #C8CEDF; border-radius: 6px; outline: none; font-size: 12px;
}
QListWidget::item { padding: 5px 10px; }
QListWidget::item:selected { background-color: #E0E8F8; color: #0099CC; }
QListWidget::item:hover { background-color: #F0F2F8; }

QSlider::groove:horizontal { background: #D0D5E8; height: 4px; border-radius: 2px; }
QSlider::handle:horizontal { background: #0099CC; width: 14px; height: 14px; margin: -5px 0; border-radius: 7px; }
QSlider::sub-page:horizontal { background: #0099CC; border-radius: 2px; }
"""

    @classmethod
    def apply(cls, app: QApplication, theme: str):
        cls.current = theme
        app.setStyleSheet(cls.DARK if theme == "dark" else cls.LIGHT)

    @classmethod
    def is_dark(cls) -> bool:
        return cls.current == "dark"

    @classmethod
    def accent_color(cls) -> str:
        return "#00E5FF" if cls.is_dark() else "#0099CC"

    @classmethod
    def text_dim_color(cls) -> str:
        return "#6B7299"

    @classmethod
    def success_color(cls) -> str:
        return "#00FF88" if cls.is_dark() else "#00AA66"

    @classmethod
    def danger_color(cls) -> str:
        return "#FF3860" if cls.is_dark() else "#C02040"

    @classmethod
    def warning_color(cls) -> str:
        return "#FFB300" if cls.is_dark() else "#E07B00"


# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD STRENGTH BAR
# ══════════════════════════════════════════════════════════════════════════════


class StrengthBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(6)
        self._score = 0

    def set_score(self, score: int):
        self._score = max(0, min(100, score))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        fill = int(w * self._score / 100)
        bg = "#1A1F2E" if ThemeManager.is_dark() else "#D0D5E8"
        painter.setBrush(QBrush(QColor(bg)))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, w, h, 3, 3)
        if fill > 0:
            color = (
                QColor("#FF3860")
                if self._score < 30
                else QColor("#FFB300") if self._score < 60 else QColor("#00FF88")
            )
            grad = QLinearGradient(0, 0, fill, 0)
            grad.setColorAt(0, color.darker(120))
            grad.setColorAt(1, color)
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(0, 0, fill, h, 3, 3)
        painter.end()


# ══════════════════════════════════════════════════════════════════════════════
#  PASSWORD INPUT WIDGET
# ══════════════════════════════════════════════════════════════════════════════


class PasswordWidget(QWidget):
    changed = pyqtSignal(str)

    def __init__(self, label="Password", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)

        lbl = QLabel(label)
        lbl.setStyleSheet(
            "color: #6B7299; font-size: 11px; font-weight: 700; letter-spacing: 1px;"
        )
        layout.addWidget(lbl)

        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.setPlaceholderText("Enter password…")
        self.input.textChanged.connect(self._on_change)

        self.toggle = QPushButton("👁")
        self.toggle.setFixedSize(34, 34)
        self.toggle.setStyleSheet(
            "QPushButton { background: #1A1F2E; border: 1px solid #2A3050; border-radius: 6px; font-size: 14px; padding: 0; }"
            "QPushButton:hover { border-color: #00E5FF; }"
        )
        self.toggle.clicked.connect(self._toggle_vis)
        row.addWidget(self.input)
        row.addWidget(self.toggle)
        layout.addLayout(row)

        self.strength_bar = StrengthBar()
        self.strength_label = QLabel("Strength: —")
        self.strength_label.setStyleSheet("color: #3D4466; font-size: 10px;")
        layout.addWidget(self.strength_bar)
        layout.addWidget(self.strength_label)

    def _toggle_vis(self):
        if self.input.echoMode() == QLineEdit.EchoMode.Password:
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle.setText("🙈")
        else:
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle.setText("👁")

    def _on_change(self, text: str):
        score = KeyManager.key_strength(text)
        self.strength_bar.set_score(score)
        labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Excellent"]
        colors = ["#FF3860", "#FF3860", "#FFB300", "#FFB300", "#00FF88", "#00FF88"]
        idx = min(5, score // 17)
        self.strength_label.setText(f"Strength: {labels[idx]}")
        self.strength_label.setStyleSheet(f"color: {colors[idx]}; font-size: 10px;")
        self.changed.emit(text)

    def text(self) -> str:
        return self.input.text()


# ══════════════════════════════════════════════════════════════════════════════
#  ALGORITHM SELECTOR PANEL  (v1)
# ══════════════════════════════════════════════════════════════════════════════


class AlgorithmPanel(QGroupBox):
    """
    Lets users choose between Fernet (default/recommended) and AES-256-GCM.
    During decryption, the algorithm is auto-detected — this panel's selection
    only affects encryption.
    """

    def __init__(self, parent=None):
        super().__init__("ENCRYPTION ALGORITHM", parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        self.combo = QComboBox()
        for alg in AlgorithmType:
            self.combo.addItem(alg.value, alg)
        layout.addWidget(self.combo)

        # Recommendation note
        self._note = QLabel()
        self._note.setWordWrap(True)
        self._note.setStyleSheet("font-size: 10px;")
        layout.addWidget(self._note)

        # Auto-detect note for decrypt
        self._decrypt_note = QLabel(
            "ℹ  During decryption the algorithm is auto-detected — "
            "no need to remember which one you used."
        )
        self._decrypt_note.setWordWrap(True)
        self._decrypt_note.setStyleSheet("color: #6B7299; font-size: 10px;")
        layout.addWidget(self._decrypt_note)

        self.combo.currentIndexChanged.connect(self._update_note)
        self._update_note()

    def _update_note(self):
        alg = self.combo.currentData()
        if alg == AlgorithmType.FERNET:
            self._note.setText(
                "★  Fernet is the recommended default.  It uses AES-128-CBC + "
                "HMAC-SHA256 for authenticated encryption and is battle-tested "
                "with the Python cryptography library."
            )
            self._note.setStyleSheet("color: #00FF88; font-size: 10px;")
        elif alg == AlgorithmType.AES_GCM:
            self._note.setText(
                "⚡  AES-256-GCM offers 256-bit keys and is faster on CPUs with "
                "AES-NI hardware acceleration.  Both algorithms are equally secure "
                "for file encryption."
            )
            self._note.setStyleSheet("color: #FFB300; font-size: 10px;")

    def selected_algorithm(self) -> AlgorithmType:
        return self.combo.currentData()

    def set_decrypt_mode(self, is_decrypt: bool):
        """Dim the selector when in decrypt mode (auto-detect takes over)."""
        self.combo.setEnabled(not is_decrypt)
        self._decrypt_note.setVisible(is_decrypt)


# ══════════════════════════════════════════════════════════════════════════════
#  OBFUSCATION SETTINGS PANEL
# ══════════════════════════════════════════════════════════════════════════════


class ObfuscationPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("FILENAME OBFUSCATION", parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        name_lbl = QLabel("Filename Strategy")
        name_lbl.setStyleSheet("color: #6B7299; font-size: 11px; font-weight: 700;")
        self.name_combo = QComboBox()
        for m in NameMode:
            self.name_combo.addItem(m.value, m)
        self.name_combo.currentIndexChanged.connect(self._update_visibility)

        self.prefix_row = QWidget()
        pr = QHBoxLayout(self.prefix_row)
        pr.setContentsMargins(0, 0, 0, 0)
        pr_lbl = QLabel("Prefix:")
        pr_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText("file_")
        pr.addWidget(pr_lbl)
        pr.addWidget(self.prefix_input)
        self.prefix_row.setVisible(False)

        ext_lbl = QLabel("Extension Strategy")
        ext_lbl.setStyleSheet("color: #6B7299; font-size: 11px; font-weight: 700;")
        self.ext_combo = QComboBox()
        for m in ExtMode:
            self.ext_combo.addItem(m.value, m)
        self.ext_combo.currentIndexChanged.connect(self._update_visibility)

        self.spoof_row = QWidget()
        sr = QHBoxLayout(self.spoof_row)
        sr.setContentsMargins(0, 0, 0, 0)
        sp_lbl = QLabel("Pick extension:")
        sp_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")
        self.spoof_picker = QComboBox()
        sr.addWidget(sp_lbl)
        sr.addWidget(self.spoof_picker)
        self.spoof_row.setVisible(False)

        self.custom_ext_row = QWidget()
        ce = QHBoxLayout(self.custom_ext_row)
        ce.setContentsMargins(0, 0, 0, 0)
        ce_lbl = QLabel("Extension:")
        ce_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")
        self.custom_ext_input = QLineEdit()
        self.custom_ext_input.setPlaceholderText(".enc")
        ce.addWidget(ce_lbl)
        ce.addWidget(self.custom_ext_input)
        self.custom_ext_row.setVisible(False)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #1A1F2E; max-height: 1px; margin: 2px 0;")

        self.manifest_check = QCheckBox(
            "Save manifest (.cg_manifest.json) for name recovery"
        )
        self.manifest_check.setChecked(False)
        self.manifest_check.toggled.connect(self._update_manifest_note)

        self._manifest_note = QLabel()
        self._manifest_note.setWordWrap(True)
        self._manifest_note.setStyleSheet("font-size: 10px;")
        self._manifest_note.setVisible(False)

        layout.addWidget(name_lbl)
        layout.addWidget(self.name_combo)
        layout.addWidget(self.prefix_row)
        layout.addWidget(ext_lbl)
        layout.addWidget(self.ext_combo)
        layout.addWidget(self.spoof_row)
        layout.addWidget(self.custom_ext_row)
        layout.addWidget(sep)
        layout.addWidget(self.manifest_check)
        layout.addWidget(self._manifest_note)

        self._update_visibility()

    def _update_visibility(self):
        name_mode = self.name_combo.currentData()
        ext_mode = self.ext_combo.currentData()
        self.prefix_row.setVisible(name_mode == NameMode.CUSTOM_PREFIX)

        spoof_map = {
            ExtMode.SPOOF_TEXT: TEXT_EXTENSIONS,
            ExtMode.SPOOF_CODE: CODE_EXTENSIONS,
            ExtMode.SPOOF_DATA: DATA_EXTENSIONS,
            ExtMode.SPOOF_MEDIA: MEDIA_EXTENSIONS,
        }
        if ext_mode in spoof_map:
            self.spoof_row.setVisible(True)
            self.spoof_picker.clear()
            self.spoof_picker.addItem("— random —", "")
            for e in spoof_map[ext_mode]:
                self.spoof_picker.addItem(e, e)
        else:
            self.spoof_row.setVisible(False)

        self.custom_ext_row.setVisible(ext_mode == ExtMode.CUSTOM_EXT)
        self._update_manifest_note()

    def _update_manifest_note(self):
        name_mode = self.name_combo.currentData()
        ext_mode = self.ext_combo.currentData()
        will_rename = name_change_required(name_mode, ext_mode)
        if will_rename:
            if not self.manifest_check.isChecked():
                self._manifest_note.setText(
                    "⚠  Filenames will change — without the manifest, "
                    "original names cannot be recovered during decryption."
                )
                self._manifest_note.setStyleSheet("color: #FFB300; font-size: 10px;")
            else:
                self._manifest_note.setText(
                    "✔  Manifest enabled — names saved and restored automatically."
                )
                self._manifest_note.setStyleSheet("color: #00FF88; font-size: 10px;")
            self._manifest_note.setVisible(True)
        else:
            if self.manifest_check.isChecked():
                self._manifest_note.setText(
                    "ℹ  Manifest will be created (optional here)."
                )
                self._manifest_note.setStyleSheet("color: #6B7299; font-size: 10px;")
                self._manifest_note.setVisible(True)
            else:
                self._manifest_note.setVisible(False)

    def name_mode(self) -> NameMode:
        return self.name_combo.currentData()

    def ext_mode(self) -> ExtMode:
        return self.ext_combo.currentData()

    def custom_prefix(self) -> str:
        return self.prefix_input.text().strip()

    def custom_ext(self) -> str:
        return self.custom_ext_input.text().strip()

    def spoof_ext_override(self) -> str:
        return self.spoof_picker.currentData() or ""

    def use_manifest(self) -> bool:
        return self.manifest_check.isChecked()


# ══════════════════════════════════════════════════════════════════════════════
#  FILE LIST WIDGET  (v1 — individual delete + tooltip)
# ══════════════════════════════════════════════════════════════════════════════


class FileListWidget(QWidget):
    """
    Draggable / browseable file and folder list.
    v1 adds: "Delete Selected" button to remove individual items,
    multi-select support, and item count display.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        hdr = QHBoxLayout()
        self._count_lbl = QLabel("0 items")
        self._count_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")

        btn_add_file = QPushButton("+ Files")
        btn_add_dir = QPushButton("+ Folder")
        # Delete Selected — removes only the highlighted rows
        btn_del_sel = QPushButton("🗑 Delete Selected")
        btn_del_sel.setObjectName("danger")
        btn_clear = QPushButton("Clear All")
        btn_clear.setObjectName("danger")

        for b in [btn_add_file, btn_add_dir, btn_del_sel, btn_clear]:
            b.setFixedHeight(27)

        btn_add_file.clicked.connect(self._add_files)
        btn_add_dir.clicked.connect(self._add_dir)
        btn_del_sel.clicked.connect(self._delete_selected)
        btn_clear.clicked.connect(self._clear)

        hdr.addWidget(self._count_lbl)
        hdr.addStretch()
        hdr.addWidget(btn_add_file)
        hdr.addWidget(btn_add_dir)
        hdr.addWidget(btn_del_sel)
        hdr.addWidget(btn_clear)
        layout.addLayout(hdr)

        self._list = QListWidget()
        self._list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        self._list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self._list.setMinimumHeight(100)
        self._list.setMaximumHeight(160)
        layout.addWidget(self._list)

        self._paths: List[Path] = []

    def _refresh(self):
        self._list.clear()
        for p in self._paths:
            icon = "📁" if p.is_dir() else "📄"
            item = QListWidgetItem(f"{icon}  {p}")
            self._list.addItem(item)
        self._count_lbl.setText(f"{len(self._paths)} item(s) selected")

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in files:
            p = Path(f)
            if p not in self._paths:
                self._paths.append(p)
        self._refresh()

    def _add_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder")
        if d:
            p = Path(d)
            if p not in self._paths:
                self._paths.append(p)
        self._refresh()

    def _delete_selected(self):
        """v1 — Remove only highlighted items from the list."""
        selected_rows = sorted(
            [self._list.row(item) for item in self._list.selectedItems()],
            reverse=True,  # remove from bottom to top to keep indices stable
        )
        for row in selected_rows:
            del self._paths[row]
        self._refresh()

    def _clear(self):
        self._paths.clear()
        self._refresh()

    def paths(self) -> List[Path]:
        return list(self._paths)


# ══════════════════════════════════════════════════════════════════════════════
#  ACTIVITY INDICATOR  (v1)
# ══════════════════════════════════════════════════════════════════════════════


class ActivityIndicator(QLabel):
    """
    Displays an animated "Encrypting…" / "Decrypting…" / "Loading…" message
    while the worker thread is running.  Stops and shows "Ready" when idle.
    """

    _DOTS = ["", ".", "..", "..."]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._base_text = "Ready"
        self._dot_idx = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setText("Ready")
        self.setStyleSheet("color: #6B7299; font-size: 12px; font-weight: 600;")

    def start(self, operation: str):
        self._base_text = operation
        self._dot_idx = 0
        self._timer.start(350)
        self._tick()

    def stop(self):
        self._timer.stop()
        self._base_text = "Ready"
        self.setText("✔  Ready")
        self.setStyleSheet("color: #00FF88; font-size: 12px; font-weight: 600;")

    def _tick(self):
        dots = self._DOTS[self._dot_idx % len(self._DOTS)]
        self.setText(f"⚙  {self._base_text}{dots}")
        self.setStyleSheet(
            f"color: {ThemeManager.accent_color()}; font-size: 12px; font-weight: 600;"
        )
        self._dot_idx += 1


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREAD  (v1 — per-file progress signal, algorithm support)
# ══════════════════════════════════════════════════════════════════════════════


class CryptoWorker(QThread):
    # Signals
    overall_progress = pyqtSignal(int, str)  # overall_pct, filename
    file_progress = pyqtSignal(int, int, str)  # current_file, total_files, filename
    log_msg = pyqtSignal(str, str)  # message, level
    finished = pyqtSignal(bool, list)  # success, list[ProcessResult]

    def __init__(
        self,
        paths: List[Path],
        password: str,
        encrypt: bool,
        algorithm: AlgorithmType,
        name_mode: NameMode,
        ext_mode: ExtMode,
        custom_prefix: str,
        custom_ext: str,
        spoof_ext_override: str,
        use_manifest: bool = True,
    ):
        super().__init__()
        self.paths = paths
        self.password = password
        self.encrypt = encrypt
        self.algorithm = algorithm
        self.name_mode = name_mode
        self.ext_mode = ext_mode
        self.custom_prefix = custom_prefix
        self.custom_ext = custom_ext
        self.spoof_ext_override = spoof_ext_override
        self.use_manifest = use_manifest
        self.dc = DirectoryCrypto()

    def run(self):
        all_results = []
        total_paths = len(self.paths)

        try:
            for idx, path in enumerate(self.paths):
                if path.is_dir():

                    def _cb(cur, total, name, idx=idx):
                        overall_pct = int(
                            ((idx + cur / max(total, 1)) / total_paths) * 100
                        )
                        self.overall_progress.emit(overall_pct, name)
                        self.file_progress.emit(cur, total, name)  # per-file

                    results = self.dc.process_directory(
                        directory=path,
                        password=self.password,
                        encrypt=self.encrypt,
                        algorithm=self.algorithm,
                        name_mode=self.name_mode,
                        ext_mode=self.ext_mode,
                        custom_prefix=self.custom_prefix,
                        custom_ext=self.custom_ext,
                        spoof_ext_override=self.spoof_ext_override,
                        use_manifest=self.use_manifest,
                        progress_callback=_cb,
                    )
                    all_results.extend(results)
                    for r in results:
                        nm = r.new_path.name if r.new_path else "?"
                        if r.success:
                            self.log_msg.emit(
                                f"✔ {r.original_path.name}  →  {nm}", "SUCCESS"
                            )
                        else:
                            self.log_msg.emit(
                                f"✘ {r.original_path.name}: {r.error}", "ERROR"
                            )
                else:
                    result = self.dc.process_single_file(
                        file_path=path,
                        password=self.password,
                        encrypt=self.encrypt,
                        algorithm=self.algorithm,
                        name_mode=self.name_mode,
                        ext_mode=self.ext_mode,
                        custom_prefix=self.custom_prefix,
                        custom_ext=self.custom_ext,
                        spoof_ext_override=self.spoof_ext_override,
                        use_manifest=self.use_manifest,
                    )
                    all_results.append(result)
                    nm = result.new_path.name if result.new_path else "?"
                    overall_pct = int(((idx + 1) / total_paths) * 100)
                    self.overall_progress.emit(overall_pct, nm)
                    self.file_progress.emit(idx + 1, total_paths, nm)  # per-file
                    if result.success:
                        self.log_msg.emit(
                            f"✔ {result.original_path.name}  →  {nm}", "SUCCESS"
                        )
                    else:
                        self.log_msg.emit(
                            f"✘ {result.original_path.name}: {result.error}", "ERROR"
                        )

            self.finished.emit(True, all_results)

        except Exception as e:
            self.log_msg.emit(f"Fatal error: {e}", "ERROR")
            self.finished.emit(False, all_results)


# ══════════════════════════════════════════════════════════════════════════════
#  LOG PANEL
# ══════════════════════════════════════════════════════════════════════════════


class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        hdr = QHBoxLayout()
        lbl = QLabel("  OPERATION LOG")
        lbl.setStyleSheet(
            "color: #6B7299; font-size: 11px; font-weight: 700; letter-spacing: 1px;"
        )
        clr = QPushButton("Clear")
        clr.setFixedHeight(28)
        clr.clicked.connect(self.clear)
        hdr.addWidget(lbl)
        hdr.addStretch()
        hdr.addWidget(clr)
        layout.addLayout(hdr)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(
            "QTextEdit { background-color: #0A0C10; border: 1px solid #1A1F2E; "
            "border-radius: 6px; font-family: Consolas, 'Courier New', monospace; "
            "font-size: 11px; padding: 8px; color: #6B7299; }"
        )
        layout.addWidget(self.log)

    def add(self, message: str, level: str = "INFO"):
        ts = QDateTime.currentDateTime().toString("HH:mm:ss")
        colors = {
            "INFO": "#6B7299",
            "SUCCESS": "#00FF88",
            "ERROR": "#FF3860",
            "WARNING": "#FFB300",
        }
        color = colors.get(level, "#6B7299")
        self.log.append(
            f'<span style="color:#2A3050">[{ts}]</span> '
            f'<span style="color:{color}">{message}</span>'
        )
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def clear(self):
        self.log.clear()


# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY DIALOG
# ══════════════════════════════════════════════════════════════════════════════


class SummaryDialog(QDialog):
    def __init__(self, results: List[ProcessResult], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Operation Summary")
        self.setMinimumSize(480, 340)

        layout = QVBoxLayout(self)
        ok_count = sum(1 for r in results if r.success)
        err_count = len(results) - ok_count

        summary = QLabel(
            f"<b style='color:#00FF88'>{ok_count} succeeded</b>  "
            f"<b style='color:#FF3860'>{err_count} failed</b>  "
            f"<span style='color:#6B7299'>out of {len(results)} files</span>"
        )
        summary.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(summary)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setStyleSheet(
            "QTextEdit { background: #0A0C10; border: 1px solid #1A1F2E; border-radius: 6px; "
            "font-family: Consolas, 'Courier New', monospace; font-size: 11px; color: #6B7299; }"
        )
        for r in results:
            if r.success:
                nm = r.new_path.name if r.new_path else "?"
                text.append(
                    f'<span style="color:#00FF88">✔</span> '
                    f'<span style="color:#E8EAFF">{r.original_path.name}</span>'
                    f'<span style="color:#2A3050"> → </span>'
                    f'<span style="color:#00E5FF">{nm}</span>'
                )
            else:
                text.append(
                    f'<span style="color:#FF3860">✘ {r.original_path.name}: {r.error}</span>'
                )
        layout.addWidget(text)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(self.accept)
        layout.addWidget(btns)


# ══════════════════════════════════════════════════════════════════════════════
#  ABOUT / INFO DIALOG  (v1)
# ══════════════════════════════════════════════════════════════════════════════


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About CryptoGraphy v1")
        self.setMinimumSize(580, 600)

        root = QVBoxLayout(self)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        hero = QLabel("CRYPTO GRAPHY")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero.setStyleSheet(
            "color: #00E5FF; font-size: 26px; font-weight: 900; "
            "letter-spacing: 10px; font-family: 'Consolas', monospace; padding: 12px 0 4px 0;"
        )
        layout.addWidget(hero)

        version_lbl = QLabel("v1.0.0  ·  Advanced File Encryption Suite")
        version_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_lbl.setStyleSheet(
            "color: #3D4466; font-size: 12px; letter-spacing: 3px;"
        )
        layout.addWidget(version_lbl)

        sep = QFrame()
        sep.setFixedHeight(2)
        sep.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 transparent, stop:0.3 #00E5FF, stop:0.7 #7B61FF, stop:1 transparent);"
        )
        layout.addWidget(sep)

        self._section(
            layout,
            "⚡  ABOUT v1",
            "CryptoGraphy v1 adds: Light/Dark theme toggle, per-file progress bar, "
            "individual file deletion from the list, file-based logging, activity "
            "indicator, and AES-256-GCM as an alternative encryption algorithm with "
            "automatic detection during decryption.",
        )

        self._section(
            layout,
            "🔐  ENCRYPTION",
            "<b style='color:#00E5FF'>Fernet</b> (default) uses AES-128-CBC + HMAC-SHA256.  "
            "<b style='color:#FFB300'>AES-256-GCM</b> uses 256-bit keys with hardware-accelerated "
            "authenticated encryption.  Both are secure — Fernet is recommended for simplicity.  "
            "During decryption the algorithm is auto-detected so you never need to remember.",
        )

        self._section(
            layout,
            "👤  CREATOR",
            "Built with <b style='color:#00E5FF'>Python</b> and "
            "<b style='color:#7B61FF'>PyQt6</b>.  "
            "Created by @Sparky2273 — DM on Telegram for support.",
        )

        layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setObjectName("accent")
        close_btn.setFixedHeight(36)
        close_btn.clicked.connect(self.accept)
        root.addWidget(close_btn)
        root.setContentsMargins(12, 0, 12, 12)

    def _section(self, layout, title, body):
        lbl = QLabel(title)
        lbl.setStyleSheet(
            "color: #00E5FF; font-size: 13px; font-weight: 800; letter-spacing: 1px; padding-top: 4px;"
        )
        layout.addWidget(lbl)
        if body:
            txt = QLabel(body)
            txt.setWordWrap(True)
            txt.setTextFormat(Qt.TextFormat.RichText)
            txt.setStyleSheet(
                "color: #A0A8CC; font-size: 12px; line-height: 160%; padding-left: 4px;"
            )
            layout.addWidget(txt)


# ══════════════════════════════════════════════════════════════════════════════
#  KEYGEN DIALOG
# ══════════════════════════════════════════════════════════════════════════════


class KeygenDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Key Generator & Inspector")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("🔑  Key Generator & Inspector")
        title.setStyleSheet("color:#00E5FF; font-size:14px; font-weight:700;")
        layout.addWidget(title)

        rkg = QGroupBox("RANDOM KEY")
        rk = QVBoxLayout(rkg)
        self.random_key_display = QLineEdit()
        self.random_key_display.setReadOnly(True)
        self.random_key_display.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px;"
        )
        gen_btn = QPushButton("Generate New Random Key")
        gen_btn.setObjectName("accent")
        gen_btn.clicked.connect(self._generate_random)
        rk.addWidget(self.random_key_display)
        rk.addWidget(gen_btn)
        layout.addWidget(rkg)

        pkg = QGroupBox("PASSWORD → KEY DERIVATION")
        pk = QVBoxLayout(pkg)
        self.pw_input = PasswordWidget("Password", self)
        self.pw_input.changed.connect(self._derive_from_password)
        self.derived_display = QLineEdit()
        self.derived_display.setReadOnly(True)
        self.derived_display.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px;"
        )
        info = QLabel("Derived key (PBKDF2-SHA256, 100k iterations):")
        info.setStyleSheet("color: #6B7299; font-size: 10px;")
        pk.addWidget(self.pw_input)
        pk.addWidget(info)
        pk.addWidget(self.derived_display)
        layout.addWidget(pkg)

        ok = QPushButton("Close")
        ok.clicked.connect(self.accept)
        layout.addWidget(ok)

        self._generate_random()

    def _generate_random(self):
        self.random_key_display.setText(KeyManager.generate_random_key().decode())

    def _derive_from_password(self, pw: str):
        if pw:
            try:
                self.derived_display.setText(KeyManager.generate_key(pw).decode())
            except Exception:
                self.derived_display.clear()
        else:
            self.derived_display.clear()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW  (v1 — layout fix, theme toggle, per-file progress, file log)
# ══════════════════════════════════════════════════════════════════════════════


class CryptoApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.worker: Optional[CryptoWorker] = None
        self._file_log_handler: Optional[logging.FileHandler] = None
        self._build_ui()
        self._setup_logging()

    # ── UI BUILD ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.setWindowTitle("CryptoGraphy v1.0.0")
        # v1: Use a more compact default size that fits all controls without
        # forcing maximize.  The left panel is wrapped in a QScrollArea so it
        # degrades gracefully on small screens.
        self.setMinimumSize(860, 620)
        self.resize(1060, 720)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(16, 12, 16, 12)
        root_layout.setSpacing(10)
        self.setCentralWidget(root)

        # ── Header row ─────────────────────────────────────────────────────────
        hdr = QHBoxLayout()

        title_lbl = QLabel("CRYPTO GRAPHY")
        title_lbl.setStyleSheet(
            f"color: {ThemeManager.accent_color()}; font-size: 20px; font-weight: 900; "
            "letter-spacing: 6px; font-family: 'Consolas', monospace;"
        )
        self._title_lbl = title_lbl  # kept so theme toggle can update color

        sub = QLabel("Advanced File Encryption Suite  v1.0.0")
        sub.setStyleSheet("color: #6B7299; font-size: 11px; letter-spacing: 2px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        # Theme toggle button (top-right of header) ────────────────────
        self._theme_btn = QPushButton("☀️  Light Mode")
        self._theme_btn.setFixedHeight(30)
        self._theme_btn.setToolTip("Toggle between Dark and Light themes")
        self._theme_btn.clicked.connect(self._toggle_theme)

        keygen_btn = QPushButton("🔑  Key Inspector")
        keygen_btn.setFixedHeight(30)
        keygen_btn.clicked.connect(self._open_keygen)

        about_btn = QPushButton("ℹ  About / Guide")
        about_btn.setFixedHeight(30)
        about_btn.clicked.connect(self._open_about)

        hdr.addWidget(title_lbl)
        hdr.addWidget(sub)
        hdr.addStretch()
        hdr.addWidget(self._theme_btn)
        hdr.addWidget(keygen_btn)
        hdr.addWidget(about_btn)
        root_layout.addLayout(hdr)

        # ── Separator ──────────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #1A1F2E; max-height: 1px;")
        root_layout.addWidget(sep)

        # ── Main splitter ──────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1A1F2E; width: 2px; }")
        root_layout.addWidget(splitter, 1)

        # ── Left panel — wrapped in a QScrollArea to fix maximize-mode bug ─────
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        left_scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
        )

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(10)
        left_scroll.setWidget(left)

        # Operation
        op_grp = QGroupBox("OPERATION")
        op_layout = QHBoxLayout(op_grp)
        self.encrypt_radio = QRadioButton("🔒  Encrypt")
        self.decrypt_radio = QRadioButton("🔓  Decrypt")
        self.encrypt_radio.setChecked(True)
        self.encrypt_radio.toggled.connect(self._on_mode_changed)
        op_layout.addWidget(self.encrypt_radio)
        op_layout.addWidget(self.decrypt_radio)
        left_layout.addWidget(op_grp)

        # File list
        fl_grp = QGroupBox("TARGET FILES / FOLDERS")
        fl_layout = QVBoxLayout(fl_grp)
        self.file_list = FileListWidget()
        fl_layout.addWidget(self.file_list)
        left_layout.addWidget(fl_grp)

        # Password
        pw_grp = QGroupBox("AUTHENTICATION")
        pw_layout = QVBoxLayout(pw_grp)
        self.password_widget = PasswordWidget("Encryption / Decryption Password", self)
        pw_layout.addWidget(self.password_widget)
        left_layout.addWidget(pw_grp)

        # Algorithm panel
        self.algo_panel = AlgorithmPanel()
        left_layout.addWidget(self.algo_panel)

        # Obfuscation
        self.obfusc_panel = ObfuscationPanel()
        left_layout.addWidget(self.obfusc_panel)

        # File logging checkbox ─────────────────────────────────────────
        log_grp = QGroupBox("LOGGING")
        log_layout = QVBoxLayout(log_grp)
        self.log_file_check = QCheckBox(
            "Save operation log to file  (cryptography.log)"
        )
        self.log_file_check.setChecked(False)
        self.log_file_check.setToolTip(
            "When enabled, all log messages with timestamps are written to\n"
            "'cryptography.log' in the application directory."
        )
        self.log_file_check.toggled.connect(self._toggle_file_logging)
        log_layout.addWidget(self.log_file_check)
        left_layout.addWidget(log_grp)

        # Start button
        self.start_btn = QPushButton("⚡  START OPERATION")
        self.start_btn.setObjectName("accent")
        self.start_btn.setFixedHeight(42)
        self.start_btn.clicked.connect(self._start)
        left_layout.addWidget(self.start_btn)

        # Progress section
        prog_grp = QGroupBox("PROGRESS")
        prog_layout = QVBoxLayout(prog_grp)
        prog_layout.setSpacing(5)

        # Activity indicator
        self.activity_lbl = ActivityIndicator()
        prog_layout.addWidget(self.activity_lbl)

        # Overall progress
        overall_row = QHBoxLayout()
        overall_lbl = QLabel("Overall:")
        overall_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")
        overall_lbl.setFixedWidth(55)
        self.overall_bar = QProgressBar()
        self.overall_bar.setFixedHeight(16)
        overall_row.addWidget(overall_lbl)
        overall_row.addWidget(self.overall_bar)
        prog_layout.addLayout(overall_row)

        # Per-file progress
        file_row = QHBoxLayout()
        file_lbl = QLabel("Current:")
        file_lbl.setStyleSheet("color: #6B7299; font-size: 11px;")
        file_lbl.setFixedWidth(55)
        self.file_bar = QProgressBar()
        self.file_bar.setFixedHeight(16)
        file_row.addWidget(file_lbl)
        file_row.addWidget(self.file_bar)
        prog_layout.addLayout(file_row)

        self.progress_label = QLabel("Ready")
        self.progress_label.setStyleSheet("color: #6B7299; font-size: 11px;")
        prog_layout.addWidget(self.progress_label)
        left_layout.addWidget(prog_grp)

        left_layout.addStretch()
        splitter.addWidget(left_scroll)

        # ── Right panel — log ──────────────────────────────────────────────────
        self.log_panel = LogPanel()
        splitter.addWidget(self.log_panel)
        splitter.setSizes([580, 340])

    # ── LOGGING SETUP ─────────────────────────────────────────────────────────

    def _setup_logging(self):
        """Route Python logging to the in-app LogPanel."""
        panel = self.log_panel

        class _Handler(logging.Handler):
            def emit(self_, record):
                lvl_map = {logging.ERROR: "ERROR", logging.WARNING: "WARNING"}
                lvl = lvl_map.get(record.levelno, "INFO")
                panel.add(self_.format(record), lvl)

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        h = _Handler()
        h.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(h)

    def _log(self, message: str, level: str = "INFO"):
        """Central log method: writes to UI panel + file if logging is enabled."""
        self.log_panel.add(message, level)
        if self._file_log_handler:
            import re

            plain = re.sub(r"<[^>]+>", "", message)
            lvl_map = {
                "SUCCESS": logging.INFO,
                "ERROR": logging.ERROR,
                "WARNING": logging.WARNING,
                "INFO": logging.INFO,
            }
            record = logging.LogRecord(
                name="CryptoGraphy",
                level=lvl_map.get(level, logging.INFO),
                pathname="",
                lineno=0,
                msg=plain,
                args=(),
                exc_info=None,
            )
            self._file_log_handler.emit(record)

    def _toggle_file_logging(self, enabled: bool):
        """v1 — enable/disable writing logs to cryptography.log."""
        root_logger = logging.getLogger()
        if enabled:
            log_path = Path(sys.argv[0]).parent / "cryptography.log"
            try:
                fh = logging.FileHandler(str(log_path), encoding="utf-8")
                fh.setFormatter(
                    logging.Formatter(
                        "%(asctime)s  [%(levelname)s]  %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                    )
                )
                root_logger.addHandler(fh)
                self._file_log_handler = fh
                self._log(f"File logging enabled → {log_path}", "INFO")
            except Exception as e:
                self._log(f"Could not open log file: {e}", "ERROR")
                self.log_file_check.setChecked(False)
        else:
            if self._file_log_handler:
                self._log("File logging disabled.", "INFO")
                root_logger.removeHandler(self._file_log_handler)
                self._file_log_handler.close()
                self._file_log_handler = None

    # ── THEME TOGGLE ──────────────────────────────────────────────────────────

    def _toggle_theme(self):
        """v1 — swap between dark and light themes."""
        app = QApplication.instance()
        new_th = "light" if ThemeManager.is_dark() else "dark"
        ThemeManager.apply(app, new_th)
        if new_th == "dark":
            self._theme_btn.setText("☀️  Light Mode")
            self._title_lbl.setStyleSheet(
                "color: #00E5FF; font-size: 20px; font-weight: 900; "
                "letter-spacing: 6px; font-family: 'Consolas', monospace;"
            )
        else:
            self._theme_btn.setText("🌙  Dark Mode")
            self._title_lbl.setStyleSheet(
                "color: #0099CC; font-size: 20px; font-weight: 900; "
                "letter-spacing: 6px; font-family: 'Consolas', monospace;"
            )

    # ── MODE CHANGE ───────────────────────────────────────────────────────────

    def _on_mode_changed(self):
        """Inform the algorithm panel whether we are decrypting (auto-detect)."""
        self.algo_panel.set_decrypt_mode(not self.encrypt_radio.isChecked())

    # ── DIALOGS ───────────────────────────────────────────────────────────────

    def _open_keygen(self):
        KeygenDialog(self).exec()

    def _open_about(self):
        AboutDialog(self).exec()

    # ── START OPERATION ───────────────────────────────────────────────────────

    def _start(self):
        paths = self.file_list.paths()
        if not paths:
            QMessageBox.warning(
                self, "No targets", "Please add files or folders to process."
            )
            return

        password = self.password_widget.text()
        if not password:
            QMessageBox.warning(self, "No password", "Please enter a password.")
            return

        encrypt = self.encrypt_radio.isChecked()
        op_str = "ENCRYPT" if encrypt else "DECRYPT"
        use_mf = self.obfusc_panel.use_manifest()
        name_mode = self.obfusc_panel.name_mode()
        ext_mode = self.obfusc_panel.ext_mode()
        algorithm = self.algo_panel.selected_algorithm()
        will_rename = name_change_required(name_mode, ext_mode)

        if encrypt and will_rename and not use_mf:
            reply = QMessageBox.warning(
                self,
                "Manifest Recommended",
                "<b style='color:#FFB300'>⚠  Filename obfuscation is on but "
                "the manifest is disabled.</b><br><br>"
                "Original filenames <b>cannot be recovered</b> automatically "
                "during decryption without the manifest.<br><br>"
                "Continue <b>without</b> the manifest?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        confirm = QMessageBox.question(
            self,
            "Confirm Operation",
            f"<b style='color:#00E5FF'>{op_str}</b> {len(paths)} item(s)?<br><br>"
            f"Algorithm: <b>{algorithm.value}</b><br>"
            f"Name mode: <b>{name_mode.value}</b><br>"
            f"Ext mode: <b>{ext_mode.value}</b><br>"
            f"Manifest: <b>{'Yes' if use_mf else 'No'}</b>",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self._log(f"Starting {op_str} on {len(paths)} item(s)…", "INFO")
        self._log(f"Algorithm: {algorithm.value}", "INFO")

        self._set_busy(True, op_str)

        self.worker = CryptoWorker(
            paths=paths,
            password=password,
            encrypt=encrypt,
            algorithm=algorithm,
            name_mode=name_mode,
            ext_mode=ext_mode,
            custom_prefix=self.obfusc_panel.custom_prefix(),
            custom_ext=self.obfusc_panel.custom_ext(),
            spoof_ext_override=self.obfusc_panel.spoof_ext_override(),
            use_manifest=use_mf,
        )
        self.worker.overall_progress.connect(self._on_overall_progress)
        self.worker.file_progress.connect(self._on_file_progress)
        self.worker.log_msg.connect(self._log)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    # ── SLOTS ─────────────────────────────────────────────────────────────────

    def _on_overall_progress(self, pct: int, name: str):
        self.overall_bar.setValue(pct)
        self.progress_label.setText(f"Processing: {name}  ({pct}%)")

    def _on_file_progress(self, cur: int, total: int, name: str):
        """v1 — Update the per-file progress bar."""
        file_pct = int((cur / max(total, 1)) * 100)
        self.file_bar.setValue(file_pct)
        self.file_bar.setFormat(f"{cur}/{total}")

    def _on_finished(self, success: bool, results: List[ProcessResult]):
        self._set_busy(False, "")
        self.overall_bar.setValue(0)
        self.file_bar.setValue(0)
        self.file_bar.setFormat("%p%")
        self.progress_label.setText("Done")

        ok = sum(1 for r in results if r.success)
        err = len(results) - ok
        msg = f"{ok} file(s) succeeded"
        if err:
            msg += f", {err} failed"

        if success and err == 0:
            self._log(f"✔ {msg}", "SUCCESS")
        else:
            self._log(f"⚠ {msg}", "WARNING")

        if results:
            SummaryDialog(results, self).exec()

    def _set_busy(self, busy: bool, op_str: str = ""):
        self.start_btn.setEnabled(not busy)
        if busy:
            action = "Encrypting" if "ENCRYPT" in op_str else "Decrypting"
            self.start_btn.setText("⏳  Running…")
            self.activity_lbl.start(f"{action}…")
        else:
            self.start_btn.setText("⚡  START OPERATION")
            self.activity_lbl.stop()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("CryptoGraphy")
    app.setApplicationVersion("1.0.0")

    try:
        app.setWindowIcon(QIcon("icon.ico"))
    except Exception:
        pass

    # Apply dark theme as default (user can toggle to light)
    ThemeManager.apply(app, "light")

    window = CryptoApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
