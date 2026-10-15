from .base import BallotType, ConfigError, InvalidBallot
from .choice import Approval, MultiChoice, SingleChoice, YesNo
from .ranked import Borda, InstantRunoff

REGISTRY: dict[str, BallotType] = {
    t.name: t for t in (SingleChoice(), YesNo(), MultiChoice(), Approval(), Borda(),
                        InstantRunoff())
}


def get(name: str) -> BallotType:
    try:
        return REGISTRY[name]
    except KeyError:
        raise ConfigError(f"unknown ballot type: {name}") from None


__all__ = ["REGISTRY", "BallotType", "ConfigError", "InvalidBallot", "get"]
