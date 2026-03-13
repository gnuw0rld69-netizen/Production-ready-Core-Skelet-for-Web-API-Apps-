from ipaddress import ip_address, ip_network

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user_ip_allowlist import UserIpAllowlist


class UserIpAllowlistService:
    @staticmethod
    def normalize_ip_or_network(value: str) -> str:
        value = value.strip()
        try:
            if "/" in value:
                return str(ip_network(value, strict=False))
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError("Invalid IP address or network") from exc

    @staticmethod
    def list_for_user(db: Session, user_id: int) -> list[UserIpAllowlist]:
        return (
            db.query(UserIpAllowlist)
            .filter(UserIpAllowlist.user_id == user_id)
            .order_by(UserIpAllowlist.id.desc())
            .all()
        )

    @staticmethod
    def create_entry(
        db: Session,
        user_id: int,
        ip_or_network: str,
        description: str | None = None,
        is_active: bool = True,
    ) -> UserIpAllowlist:
        normalized = UserIpAllowlistService.normalize_ip_or_network(ip_or_network)
        entry = UserIpAllowlist(
            user_id=user_id,
            ip_or_network=normalized,
            description=description,
            is_active=is_active,
        )
        db.add(entry)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ValueError("IP or network already exists") from exc
        db.refresh(entry)
        return entry

    @staticmethod
    def update_entry(
        db: Session,
        user_id: int,
        entry_id: int,
        ip_or_network: str | None = None,
        description: str | None = None,
        is_active: bool | None = None,
    ) -> UserIpAllowlist | None:
        entry = (
            db.query(UserIpAllowlist)
            .filter(
                UserIpAllowlist.user_id == user_id,
                UserIpAllowlist.id == entry_id,
            )
            .first()
        )
        if not entry:
            return None

        if ip_or_network is not None:
            entry.ip_or_network = UserIpAllowlistService.normalize_ip_or_network(ip_or_network)
        if description is not None:
            entry.description = description
        if is_active is not None:
            entry.is_active = is_active

        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ValueError("IP or network already exists") from exc
        db.refresh(entry)
        return entry

    @staticmethod
    def delete_entry(db: Session, user_id: int, entry_id: int) -> bool:
        entry = (
            db.query(UserIpAllowlist)
            .filter(
                UserIpAllowlist.user_id == user_id,
                UserIpAllowlist.id == entry_id,
            )
            .first()
        )
        if not entry:
            return False
        db.delete(entry)
        db.commit()
        return True

    @staticmethod
    def is_ip_allowed(db: Session, user_id: int, client_ip: str | None) -> bool:
        entries = (
            db.query(UserIpAllowlist)
            .filter(
                UserIpAllowlist.user_id == user_id,
                UserIpAllowlist.is_active.is_(True),
            )
            .all()
        )
        if not entries:
            return True
        if not client_ip:
            return False
        try:
            parsed_ip = ip_address(client_ip)
        except ValueError:
            return False

        for entry in entries:
            try:
                if parsed_ip in ip_network(entry.ip_or_network, strict=False):
                    return True
            except ValueError:
                continue
        return False
