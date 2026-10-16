import os
import hmac
import hashlib
import secrets
import base64
import time
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import asyncpg
import httpx

PEPPER = bytes.fromhex(os.environ["KEY_PEPPER"])
ADMIN_KEY = os.environ["ADMIN_KEY"]
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

app = FastAPI()
pool: asyncpg.Pool = None


def key_hash(k: str) -> str:
    norm = k.upper().replace("-", "").strip()
    return hmac.new(PEPPER, norm.encode(), hashlib.sha256).hexdigest()


def gen_key() -> str:
    raw = secrets.token_bytes(13)
    s = base64.b32encode(raw).decode().rstrip("=")
    s = "".join(c for c in s if c in ALPHABET)[:20]
    return "GXY-" + "-".join(s[i:i+5] for i in range(0, 20, 5))


async def verify_turnstile(token: str) -> bool:
    if not TURNSTILE_SECRET:
        return True  # dev mode — no turnstile configured
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": TURNSTILE_SECRET, "response": token},
        )
        return r.json().get("success", False)


class RedeemIn(BaseModel):
    key: str
    email: str | None = None
    turnstile: str | None = None


class ValidateIn(BaseModel):
    token: str
    hwid: str


@app.on_event("startup")
async def startup():
    global pool
    pool = await asyncpg.create_pool(
        os.environ["DATABASE_URL"],
        ssl="require",
        min_size=1,
        max_size=4,
    )


@app.on_event("shutdown")
async def shutdown():
    if pool:
        await pool.close()


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/api/redeem")
async def redeem(body: RedeemIn):
    if body.turnstile:
        ok = await verify_turnstile(body.turnstile)
        if not ok:
            raise HTTPException(403, "turnstile failed")

    h = key_hash(body.key)
    async with pool.acquire() as con:
        async with con.transaction():
            row = await con.fetchrow(
                "SELECT id, tier, hwid_slots, redeemed_at, revoked, expires_at, batch_id "
                "FROM license_keys WHERE key_hash=$1 FOR UPDATE",
                h,
            )
            if not row:
                raise HTTPException(404, "invalid key")
            if row["revoked"]:
                raise HTTPException(410, "revoked")
            if row["redeemed_at"] is not None:
                raise HTTPException(409, "already redeemed")

            batch = await con.fetchrow(
                "SELECT active FROM key_batches WHERE batch_id=$1",
                row["batch_id"],
            )
            if batch and not batch["active"]:
                raise HTTPException(410, "batch expired")

            token = secrets.token_urlsafe(48)
            await con.execute(
                "UPDATE license_keys SET redeemed_at=now(), license_token=$1, "
                "expires_at = now() + interval '1 day' WHERE id=$2",
                token,
                row["id"],
            )
            return {"ok": True, "token": token, "tier": row["tier"]}


@app.post("/v1/validate")
async def validate(body: ValidateIn):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT id, tier, hwid_slots, hwid_list, expires_at, revoked "
            "FROM license_keys WHERE license_token=$1",
            body.token,
        )
        if not row or row["revoked"]:
            raise HTTPException(403, "denied")
        if row["expires_at"].timestamp() < time.time():
            raise HTTPException(403, "expired")

        hwids = row["hwid_list"] or []
        if body.hwid not in hwids:
            if len(hwids) >= row["hwid_slots"]:
                raise HTTPException(403, "hwid_limit")
            await con.execute(
                "UPDATE license_keys SET hwid_list = array_append(hwid_list, $1) WHERE id=$2",
                body.hwid,
                row["id"],
            )
        return {
            "ok": True,
            "tier": row["tier"],
            "expires": row["expires_at"].isoformat(),
        }


@app.post("/v1/keys/generate")
async def generate(
    x_admin_key: str = Header(...),
    count: int = 1,
    tier: str = "week",
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "denied")
    async with pool.acquire() as con:
        batch = await con.fetchrow(
            "INSERT INTO key_batches DEFAULT VALUES RETURNING batch_id"
        )
        keys = []
        for _ in range(count):
            k = gen_key()
            await con.execute(
                "INSERT INTO license_keys (key_hash, batch_id, tier) VALUES ($1,$2,$3)",
                key_hash(k),
                batch["batch_id"],
                tier,
            )
            keys.append(k)
        return {"keys": keys, "batch": str(batch["batch_id"])}


@app.post("/admin/rotate")
async def rotate(x_admin_key: str = Header(...)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "denied")
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE license_keys SET revoked=true "
            "WHERE redeemed_at IS NULL AND revoked=false "
            "AND issued_at < now() - interval '1 day'"
        )
        await con.execute(
            "UPDATE key_batches SET active=false WHERE created_at < now() - interval '2 days'"
        )
        await con.execute("INSERT INTO key_batches DEFAULT VALUES")
    return {"ok": True}
