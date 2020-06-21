import click
from flask.cli import with_appcontext
from .models import db


@click.command()
@with_appcontext
def create_db():
    "Create database models"
    db.create_all()
    db.session.commit()
    print("Database tables created")
