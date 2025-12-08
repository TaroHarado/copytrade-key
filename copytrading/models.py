"""
Copytrading Models (READ-ONLY для валидации)

⚠️ Эти модели используются ТОЛЬКО для чтения из copytrading БД
⚠️ Никогда не создавайте/удаляйте записи через эти модели!
"""
from sqlalchemy import Integer, String, DateTime, Boolean, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from core.database.config import Base
from datetime import datetime


class TargetActivity(Base):
    """
    Target activity from copytrading service (READ-ONLY)
    
    Используется для валидации ордеров.
    """
    __tablename__ = "target_activities"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    activity_id: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    wallet_address: Mapped[str] = mapped_column(String(42), nullable=False, index=True)
    token_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    side: Mapped[str] = mapped_column(String(10), nullable=False)  # "BUY" or "SELL"
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    price: Mapped[float | None] = mapped_column(Float, nullable=True)
    usdc_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    user_activities: Mapped[list["UserActivity"]] = relationship(back_populates="target_activity")


class MonitoringSession(Base):
    """
    Monitoring session from copytrading service (READ-ONLY)
    
    Используется для валидации что пользователь копирует цель.
    """
    __tablename__ = "monitoring_sessions"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    target_address: Mapped[str] = mapped_column(String(42), nullable=False, index=True)
    internal_wallet_address: Mapped[str] = mapped_column(String(42), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserActivity(Base):
    """
    User activity from copytrading service (READ + UPDATE для replay protection)
    
    ⚠️ UPDATE только для is_order_signed и is_commission_signed!
    """
    __tablename__ = "user_activities"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    target_activity_id: Mapped[int] = mapped_column(
        Integer, 
        ForeignKey('target_activities.id'), 
        nullable=False,
        index=True
    )
    
    # Trade details
    usdc_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    token_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    price: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    # Replay protection flags (UPDATE разрешен только для этих полей!)
    is_order_signed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_commission_signed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    target_activity: Mapped["TargetActivity"] = relationship(back_populates="user_activities")




