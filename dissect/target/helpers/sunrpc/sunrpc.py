from __future__ import annotations


from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar


class MessageType(Enum):
    CALL = 0
    REPLY = 1


class ReplyStats(Enum):
    MSG_ACCEPTED = 0
    MSG_DENIED = 1


class AcceptStat(Enum):
    SUCCESS = 0  # RPC executed successfully
    PROG_UNAVAIL = 1  # remote hasn't exported program
    PROG_MISMATCH = 2  # remote can't support version #
    PROC_UNAVAIL = 3  # program can't support procedure
    GARBAGE_ARGS = 4  # procedure can't decode params


class RejectStat(Enum):
    RPC_MISMATCH = 0
    AUTH_ERROR = 1


class AuthStat(Enum):
    AUTH_BADCRED = 1  # bad credentials (seal broken)
    AUTH_REJECTEDCRED = 2  # client must begin new session
    AUTH_BADVERF = 3  # bad verifier (seal broken)
    AUTH_REJECTEDVERF = 4  # verifier expired or replayed
    AUTH_TOOWEAK = 5  # rejected for security reasons


ProcedureParams = TypeVar('ProcedureParams')
ProcedureResults = TypeVar('ProcedureResults')
Auth = TypeVar('Auth')
Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")


@dataclass
class AuthNull():
    pass


@dataclass
class CallBody(Generic[ProcedureParams, Credentials, Verifier]):
    rpc_version: int
    program: int
    version: int
    procedure: int
    cred: Credentials
    verf: Verifier
    params: ProcedureParams


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
    type: MessageType
    body: CallBody[ProcedureParams, Credentials, Verifier] | AcceptedReply[ProcedureResults, Verifier] | RejectedReply
