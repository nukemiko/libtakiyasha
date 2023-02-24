# -*- coding: utf-8 -*-
from __future__ import annotations

from .exceptions import LibTakiyashaException
from .kgmvpr import (
    KGMorVPR,
    KGMorVPRFileInfo,
    probe_kgmvpr,
    probeinfo_kgmvpr
)
from .kwm import (
    KWM,
    KWMFileInfo,
    probe_kwm,
    probeinfo_kwm
)
from .ncm import (CloudMusicIdentifier, NCM, NCMFileInfo, probe_ncm, probeinfo_ncm)
from .pkgmetadata import (
    version,
    version_info
)
from .qmc import (
    QMCFileInfo,
    QMCv1,
    QMCv2,
    probe_qmc,
    probe_qmcv1,
    probe_qmcv2,
    probeinfo_qmc,
    probeinfo_qmcv1,
    probeinfo_qmcv2
)
from .warns import LibTakiyashaWarning
