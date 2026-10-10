"""Initial migration avec User et BackupCode"""

from alembic import op
import sqlalchemy as sa

revision = '3e94025ac24e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(80), nullable=False),
        sa.Column('email', sa.String(120), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('mfa_secret', sa.String(64), nullable=True),
        sa.Column(
            'mfa_enabled',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false()
        ),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_totp_code', sa.String(10), nullable=True),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email'),
    )

    op.create_table(
        'backup_codes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('code_hash', sa.String(255), nullable=False),
        sa.Column(
            'used',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false()
        ),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )


def downgrade():
    op.drop_table('backup_codes')
    op.drop_table('users')