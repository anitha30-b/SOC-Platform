from fastapi import APIRouter, HTTPException
import httpx

router = APIRouter(prefix="/juice-shop", tags=["Juice Shop"])

JUICE_SHOP_URL = "http://127.0.0.1:3000"


@router.get("/status")
async def juice_shop_status():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{JUICE_SHOP_URL}/api/Challenges")

        if response.status_code != 200:
            return {
                "status": "unhealthy",
                "url": JUICE_SHOP_URL,
                "http_status": response.status_code,
            }

        payload = response.json()
        challenges = payload.get("data", [])

        return {
            "status": "running",
            "url": JUICE_SHOP_URL,
            "http_status": response.status_code,
            "api_status": payload.get("status"),
            "challenge_count": len(challenges),
            "solved_count": sum(
                1 for challenge in challenges
                if challenge.get("solved") is True
            ),
        }

    except Exception as exc:
        return {
            "status": "offline",
            "url": JUICE_SHOP_URL,
            "error": str(exc),
        }


@router.get("/challenges")
async def juice_shop_challenges():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{JUICE_SHOP_URL}/api/Challenges")

        response.raise_for_status()
        payload = response.json()

        return {
            "status": payload.get("status"),
            "target": JUICE_SHOP_URL,
            "data": payload.get("data", []),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to reach Juice Shop: {exc}",
        )
