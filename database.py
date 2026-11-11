from sqlmodel import SQLModel, create_engine

import models


DATABASE_URL = "sqlite:///data/attack_surface.db"

engine = create_engine(
    DATABASE_URL,
    echo=False,
)


def init_db():
    SQLModel.metadata.create_all(engine)