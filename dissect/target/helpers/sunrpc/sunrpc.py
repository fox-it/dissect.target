from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Generic, NamedTuple, TypeVar


class ProcedureDescriptor(NamedTuple):
    program: int
    version: int
    procedure: int


GetPortProc = ProcedureDescriptor(100000, 2, 3)


class Bool(IntEnum):
    FALSE = 0
    TRUE = 1


class AcceptStat(IntEnum):
    SUCCESS = 0  # RPC executed successfully
    PROG_UNAVAIL = 1  # remote hasn't exported program
    PROG_MISMATCH = 2  # remote can't support version #
    PROC_UNAVAIL = 3  # program can't support procedure
    GARBAGE_ARGS = 4  # procedure can't decode params


class RejectStat(IntEnum):
    RPC_MISMATCH = 0
    AUTH_ERROR = 1


class AuthStat(IntEnum):
    AUTH_BADCRED = 1  # bad credentials (seal broken)
    AUTH_REJECTEDCRED = 2  # client must begin new session
    AUTH_BADVERF = 3  # bad verifier (seal broken)
    AUTH_REJECTEDVERF = 4  # verifier expired or replayed
    AUTH_TOOWEAK = 5  # rejected for security reasons


ProcedureParams = TypeVar("ProcedureParams")
ProcedureResults = TypeVar("ProcedureResults")
Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")


@dataclass
class AuthNull:
    pass


@dataclass
class AuthUnix:
    stamp: int  # Arbitrary id
    machinename: str
    uid: int
    gid: int
    gids: list[int]

    def __post_init__(self):
        if len(self.gids) > 16:
            raise ValueError("gids list cannot exceed 16 elements")

        if len(self.machinename) > 255:
            raise ValueError("machinename cannot exceed 255 characters")


@dataclass
class CallBody(Generic[ProcedureParams, Credentials, Verifier]):
    program: int
    version: int
    procedure: int
    cred: Credentials
    verf: Verifier
    params: ProcedureParams
    rpc_version: int = 2


@dataclass
class Mismatch:
    low: int
    high: int


@dataclass
class AcceptedReply(Generic[ProcedureResults, Verifier]):
    verf: Verifier
    stat: AcceptStat
    results: ProcedureResults | Mismatch | None


@dataclass
class RejectedReply:
    stat: RejectStat
    result: Mismatch | AuthStat


@dataclass
class Message(Generic[ProcedureParams, ProcedureResults, Credentials, Verifier]):
    xid: int
    body: CallBody[ProcedureParams, Credentials, Verifier] | AcceptedReply[ProcedureResults, Verifier] | RejectedReply


class Protocol(IntEnum):
    TCP = 6
    UDP = 17


@dataclass
class PortMapping:
    program: int
    version: int
    protocol: Protocol
    port: int = 0
