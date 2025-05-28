import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import RedirectResponse

from mediaflow_proxy.speedtest.service import SpeedTestService, SpeedTestProvider

speedtest_router = APIRouter()

# Initialize service
speedtest_service = SpeedTestService()


@speedtest_router.get("/", summary="Show speed test interface")
async def show_speedtest_page():
    """Return the speed test HTML interface."""
    return RedirectResponse(url="/speedtest.html")


@speedtest_router.post("/start", summary="Start a new speed test", response_model=dict)
async def start_speedtest(background_tasks: BackgroundTasks, provider: SpeedTestProvider, request: Request):
    """Start a new speed test for the specified provider."""
    task_id = str(uuid.uuid4())
    api_key = request.headers.get("api_key")

    # Create and initialize the task
    await speedtest_service.create_test(task_id, provider, api_key)

    # Schedule the speed test
    background_tasks.add_task(speedtest_service.run_speedtest, task_id, provider, api_key)

    return {"task_id": task_id}


@speedtest_router.get("/results/{task_id}", summary="Get speed test results")
async def get_speedtest_results(task_id: str):
    """Get the results or current status of a speed test."""
    task = await speedtest_service.get_test_results(task_id)

    if not task:
        raise HTTPException(status_code=404, detail="Speed test task not found or expired")

    return task.dict()
