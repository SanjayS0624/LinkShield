from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import require_roles
from app.database.session import get_db
from app.models.brand import Brand
from app.schemas.brands import BrandInput, BrandView

router = APIRouter(prefix="/api/brands", tags=["brands"])


@router.get("", response_model=list[BrandView])
def list_brands(db: Session = Depends(get_db)) -> list[BrandView]:
    return [BrandView.model_validate(brand) for brand in db.scalars(select(Brand).order_by(Brand.name)).all()]


@router.post("", response_model=BrandView, status_code=status.HTTP_201_CREATED)
def create_brand(payload: BrandInput, db: Session = Depends(get_db), _admin=Depends(require_roles("admin"))) -> BrandView:
    brand = Brand(**payload.model_dump())
    db.add(brand)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A brand with this name already exists") from None
    db.refresh(brand)
    return BrandView.model_validate(brand)


@router.put("/{brand_id}", response_model=BrandView)
def update_brand(brand_id: UUID, payload: BrandInput, db: Session = Depends(get_db), _admin=Depends(require_roles("admin"))) -> BrandView:
    brand = db.get(Brand, brand_id)
    if brand is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand not found")
    for key, value in payload.model_dump().items():
        setattr(brand, key, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A brand with this name already exists") from None
    db.refresh(brand)
    return BrandView.model_validate(brand)


@router.delete("/{brand_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_brand(brand_id: UUID, db: Session = Depends(get_db), _admin=Depends(require_roles("admin"))) -> Response:
    brand = db.get(Brand, brand_id)
    if brand is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Brand not found")
    db.delete(brand)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
