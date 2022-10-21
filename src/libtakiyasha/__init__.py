# -*- coding: utf-8 -*-
from __future__ import annotations

from .common import CipherSkel, CryptLayerWrappedIOSkel, StreamCipherSkel
from .exceptions import CipherDecryptingError, CipherEncryptingError, CrypterCreatingError, CrypterSavingError, LibTakiyashaException
from .keyutils import make_random_alphabet_string, make_random_ascii_string, make_random_number_string, make_salt
from .ncm import CloudMusicIdentifier, NCM
from .pkgver import progname, version
from .qmc import QMCv1, QMCv2, QMCv2QTag, QMCv2STag
from .qmc.dataciphers import HardenedRC4, Mask128
from .qmc.keyciphers import QMCv2KeyEncryptV1, QMCv2KeyEncryptV2, make_simple_key
from .stdciphers import ARC4, StreamedAESWithModeECB, TEAWithModeECB, TencentTEAWithModeCBC
from .typedefs import CipherProto, StreamCipherBasedCryptedIOProto, StreamCipherProto
from .warns import CipherDecryptingWarning, CipherEncryptingWarning, CrypterCreatingWarning, CrypterSavingWarning, LibTakiyashaWarning
