import json
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Assessment,
    QARecord,
    QATestResource,
    User,
)
from rbac import require_role
from schemas import (
    QAUISaveRequest,
    QAUIUXTargetReviewRequest,
    QAMarketSaveRequest,
    QAAPIRequest,
    QARecordResponse,
    QADiscoverRequest,
    QADiscoverResponse,
    QAEndpointInfo,
    QATestResourceResponse,
    QAFullAPITestRequest,
    QAFullAPITestResponse,
    QATestStepResponse,
)


# ==================================================
# QA ROUTER
# ==================================================

router = APIRouter(
    prefix="/qa",
    tags=["QA Testing"],
)


# ==================================================
# URL VALIDATION
# ==================================================

def validate_target_url(target: str):
    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Target must use HTTP or HTTPS.",
        )

    if not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Invalid target URL.",
        )

    return parsed


def validate_target_endpoint(
    target: str,
    endpoint_url: str,
):
    target_url = validate_target_url(target)
    endpoint = validate_target_url(endpoint_url)

    if (
        target_url.scheme != endpoint.scheme
        or target_url.netloc.lower() != endpoint.netloc.lower()
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "API endpoint must belong to the active VAPT target: "
                f"{target}"
            ),
        )


# ==================================================
# ASSESSMENT HELPERS
# ==================================================

def normalize_target(target: str) -> str:
    """
    Normalize target URLs so:
    http://example.com
    and
    http://example.com/
    are treated as the same target.
    """

    return target.strip().rstrip("/")


def find_assessment(
    db: Session,
    current_user: User,
    target: str,
):
    normalized_target = normalize_target(target)

    assessments = (
        db.query(Assessment)
        .filter(
            Assessment.user_id == current_user.id
        )
        .order_by(
            Assessment.created_at.desc()
        )
        .all()
    )

    for assessment in assessments:
        if (
            normalize_target(
                assessment.target
            )
            == normalized_target
        ):
            return assessment

    return None


def update_assessment_qa(
    db: Session,
    current_user: User,
    target: str,
    score: int,
):
    """
    Update the QA status and score of the same assessment
    created by the VAPT scan.
    """

    assessment = find_assessment(
        db=db,
        current_user=current_user,
        target=target,
    )

    if assessment is None:
        return None

    safe_score = max(
        0,
        min(100, int(score)),
    )

    assessment.qa_status = "completed"
    assessment.qa_score = safe_score
    assessment.overall_status = "active"

    db.commit()
    db.refresh(assessment)

    return assessment


# ==================================================
# AUTOMATED UI / UX TARGET REVIEW
# ==================================================

class UIUXHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.in_title = False

        self.title_parts = []

        self.has_viewport = False
        self.has_lang = False

        self.heading_count = 0

        self.image_count = 0
        self.image_alt_count = 0

        self.link_count = 0

    def handle_starttag(
        self,
        tag,
        attrs,
    ):
        tag = tag.lower()

        attributes = dict(attrs)

        if tag == "title":
            self.in_title = True

        elif tag == "html":
            self.has_lang = bool(
                (attributes.get("lang") or "").strip()
            )

        elif tag == "meta":

            name = (
                attributes.get("name")
                or ""
            ).lower()

            if name == "viewport":
                self.has_viewport = True

        elif tag in {
            "h1",
            "h2",
            "h3",
        }:
            self.heading_count += 1

        elif tag == "img":

            self.image_count += 1

            alt_value = (
                attributes.get("alt") or ""
            ).strip()

            if alt_value:
                self.image_alt_count += 1

        elif tag == "a":
            self.link_count += 1

    def handle_endtag(self, tag):

        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):

        if self.in_title:

            text = data.strip()

            if text:
                self.title_parts.append(text)


def analyze_uiux_target(
    response,
    response_time_ms: int,
):
    content_type = (
        response.headers.get(
            "content-type",
            "",
        )
        .lower()
    )

    is_html = (
        "text/html"
        in content_type
    )

    html = (
        response.text[:500_000]
        if is_html
        else ""
    )

    parser = UIUXHTMLParser()

    if is_html:

        try:
            parser.feed(html)

        except Exception:
            pass

    responsive_pass = (
        is_html
        and parser.has_viewport
    )

    navigation_pass = (
        is_html
        and parser.link_count > 0
    )

    accessibility_pass = (
        is_html
        and parser.has_lang
        and parser.heading_count > 0
        and (
            parser.image_count == 0
            or
            parser.image_alt_count
            == parser.image_count
        )
    )

    performance_pass = (
        response_time_ms <= 1000
    )

    visual_consistency_pass = (
        is_html
        and bool(parser.title_parts)
        and parser.heading_count > 0
    )

    checks = {

        "responsive": {
            "label": "Responsive layout",

            "pass": responsive_pass,

            "details": (
                "Viewport metadata was detected."
                if responsive_pass
                else
                "Responsive viewport metadata "
                "was not detected."
            ),
        },

        "navigation": {
            "label": "Navigation",

            "pass": navigation_pass,

            "details": (
                f"Detected {parser.link_count} "
                "navigation link(s)."
                if navigation_pass
                else
                "No navigation links were detected."
            ),
        },

        "accessibility": {
            "label": "Accessibility",

            "pass": accessibility_pass,

            "details": (
                "Language, heading and image-alt "
                "checks passed."
                if accessibility_pass
                else
                "Review document language, heading "
                "structure and image alternative text."
            ),
        },

        "performance": {
            "label": "Performance",

            "pass": performance_pass,

            "details": (
                f"Initial HTTP response completed "
                f"in {response_time_ms} ms."
                if performance_pass
                else
                f"Initial HTTP response took "
                f"{response_time_ms} ms."
            ),
        },

        "visual_consistency": {
            "label": "Visual consistency",

            "pass": visual_consistency_pass,

            "details": (
                "Page title and heading structure "
                "were detected."
                if visual_consistency_pass
                else
                "Title or heading structure needs review."
            ),
        },
    }

    passed = sum(
        1
        for check in checks.values()
        if check["pass"]
    )

    total = len(checks)

    score = round(
        (passed / total) * 100
    ) if total else 0

    summary = (
        f"{passed} of {total} automated "
        "UI/UX checks passed. "
        "This is a heuristic review and should "
        "be supplemented by human validation."
    )

    page_title = " ".join(
        parser.title_parts
    ).strip()

    return (
        parser,
        checks,
        score,
        summary,
        page_title or None,
    )


# ==================================================
# AUTOMATED UI / UX REVIEW
# ==================================================

@router.post(
    "/uiux-test"
)
def run_uiux_target_review(
    payload: QAUIUXTargetReviewRequest,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    target = payload.target.strip()

    validate_target_url(target)

    started = time.perf_counter()

    try:

        with httpx.Client(
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
            headers={
                "Accept": (
                    "text/html,"
                    "application/xhtml+xml,"
                    "text/plain,"
                    "*/*"
                ),
                "User-Agent":
                    "SOC-Platform-QA-UIUX/1.0",
            },
        ) as client:

            response = client.get(
                target
            )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail=(
                "UI/UX target timed out."
            ),
        )

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to reach UI/UX target: "
                f"{exc}"
            ),
        )

    response_time_ms = round(
        (
            time.perf_counter()
            - started
        )
        * 1000,
        2,
    )

    (
        parser,
        checks,
        uiux_score,
        summary,
        page_title,
    ) = analyze_uiux_target(
        response=response,
        response_time_ms=int(
            response_time_ms
        ),
    )

    # ----------------------------------------------
    # Save QA record
    # ----------------------------------------------

    record = QARecord(
        user_id=current_user.id,

        test_type="uiux",

        target=target,

        responsive=bool(
            checks[
                "responsive"
            ]["pass"]
        ),

        navigation=bool(
            checks[
                "navigation"
            ]["pass"]
        ),

        accessibility=bool(
            checks[
                "accessibility"
            ]["pass"]
        ),

        performance=bool(
            checks[
                "performance"
            ]["pass"]
        ),

        visual_consistency=bool(
            checks[
                "visual_consistency"
            ]["pass"]
        ),

        uiux_score=uiux_score,
    )

    db.add(record)

    db.commit()

    db.refresh(record)

    # ----------------------------------------------
    # Update the Assessment
    # ----------------------------------------------

    update_assessment_qa(
        db=db,
        current_user=current_user,
        target=target,
        score=uiux_score,
    )

    return {

        "id": record.id,

        "user_id":
            current_user.id,

        "test_type":
            "uiux",

        "target":
            target,

        "uiux_score":
            uiux_score,

        "http_status":
            response.status_code,

        "response_time_ms":
            int(response_time_ms),

        "page_title":
            page_title,

        "checks":
            checks,

        "summary":
            summary,

        "created_at":
            record.created_at,
    }


# ==================================================
# API DISCOVERY
# ==================================================

@router.post(
    "/discover",
    response_model=QADiscoverResponse,
)
def discover_api_endpoints(
    payload: QADiscoverRequest,
    current_user: User = Depends(
        require_role(1)
    ),
):
    target = payload.target.strip()

    validate_target_url(target)

    candidates = [

        urljoin(
            target.rstrip("/") + "/",
            "openapi.json",
        ),

        urljoin(
            target.rstrip("/") + "/",
            "swagger.json",
        ),
    ]

    endpoints = []

    openapi_url = None

    openapi_version = None

    try:

        with httpx.Client(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True,
            headers={
                "Accept": "application/json",
                "User-Agent":
                    "SOC-Platform-QA-Discovery/1.0",
            },
        ) as client:

            for candidate in candidates:

                try:

                    response = client.get(
                        candidate
                    )

                    if response.status_code != 200:
                        continue

                    document = response.json()

                    if (
                        not isinstance(
                            document,
                            dict,
                        )
                        or
                        "paths"
                        not in document
                    ):
                        continue

                    openapi_url = candidate

                    openapi_version = (
                        document.get(
                            "openapi"
                        )
                        or
                        document.get(
                            "swagger"
                        )
                    )

                    for path, path_data in document[
                        "paths"
                    ].items():

                        if not isinstance(
                            path_data,
                            dict,
                        ):
                            continue

                        methods = []

                        for method in (
                            "GET",
                            "POST",
                            "PUT",
                            "DELETE",
                        ):

                            if (
                                method.lower()
                                in path_data
                            ):
                                methods.append(
                                    method
                                )

                        if not methods:
                            continue

                        first_operation = (
                            path_data.get(
                                methods[0].lower(),
                                {}
                            )
                        )

                        endpoints.append(
                            QAEndpointInfo(
                                path=path,

                                methods=methods,

                                summary=(
                                    first_operation.get(
                                        "summary"
                                    )
                                    if isinstance(
                                        first_operation,
                                        dict,
                                    )
                                    else None
                                ),

                                operation_id=(
                                    first_operation.get(
                                        "operationId"
                                    )
                                    if isinstance(
                                        first_operation,
                                        dict,
                                    )
                                    else None
                                ),
                            )
                        )

                    break

                except (
                    httpx.RequestError,
                    ValueError,
                ):
                    continue

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to reach API definition: "
                f"{exc}"
            ),
        )

    if not endpoints:

        raise HTTPException(
            status_code=404,
            detail=(
                "No OpenAPI/Swagger API definition "
                "was found at the target."
            ),
        )

    return QADiscoverResponse(

        target=target,

        openapi_url=openapi_url,

        openapi_version=openapi_version,

        endpoint_count=len(
            endpoints
        ),

        endpoints=endpoints,
    )


# ==================================================
# SAFE QA TEST RESOURCE
# ==================================================

@router.post(
    "/test-resource",
    response_model=QATestResourceResponse,
    status_code=201,
)
def create_qa_test_resource(
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    resource = QATestResource(

        user_id=current_user.id,

        name=(
            f"SOC QA Test "
            f"{int(time.time())}"
        ),

        description=(
            "Temporary resource created "
            "for automated QA testing."
        ),
    )

    db.add(resource)

    db.commit()

    db.refresh(resource)

    return resource


@router.get(
    "/test-resource/{resource_id}",
    response_model=QATestResourceResponse,
)
def get_qa_test_resource(
    resource_id: int,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    resource = (
        db.query(QATestResource)
        .filter(
            QATestResource.id
            == resource_id,

            QATestResource.user_id
            == current_user.id,
        )
        .first()
    )

    if not resource:

        raise HTTPException(
            status_code=404,
            detail="QA test resource not found.",
        )

    return resource


@router.put(
    "/test-resource/{resource_id}",
    response_model=QATestResourceResponse,
)
def update_qa_test_resource(
    resource_id: int,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    resource = (
        db.query(QATestResource)
        .filter(
            QATestResource.id
            == resource_id,

            QATestResource.user_id
            == current_user.id,
        )
        .first()
    )

    if not resource:

        raise HTTPException(
            status_code=404,
            detail="QA test resource not found.",
        )

    resource.name = (
        resource.name
        + " Updated"
    )

    resource.description = (
        "Temporary QA resource "
        "updated successfully."
    )

    db.commit()

    db.refresh(resource)

    return resource


@router.delete(
    "/test-resource/{resource_id}",
    status_code=204,
)
def delete_qa_test_resource(
    resource_id: int,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    resource = (
        db.query(QATestResource)
        .filter(
            QATestResource.id
            == resource_id,

            QATestResource.user_id
            == current_user.id,
        )
        .first()
    )

    if not resource:

        raise HTTPException(
            status_code=404,
            detail="QA test resource not found.",
        )

    db.delete(resource)

    db.commit()

    return None


# ==================================================
# FULL AUTOMATED CRUD QA
# ==================================================

@router.post(
    "/run-api-suite",
    response_model=QAFullAPITestResponse,
)
def run_full_api_suite(
    payload: QAFullAPITestRequest,
    current_user: User = Depends(
        require_role(1)
    ),
    db: Session = Depends(get_db),
):
    target = payload.target.strip()

    validate_target_url(target)

    steps = []

    # ==================================================
    # POST
    # ==================================================

    started = time.perf_counter()

    try:

        resource = QATestResource(

            user_id=current_user.id,

            name=(
                f"SOC Automated QA "
                f"{int(time.time())}"
            ),

            description=(
                "Temporary automated QA resource."
            ),
        )

        db.add(resource)

        db.commit()

        db.refresh(resource)

        post_time = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        steps.append(
            QATestStepResponse(

                method="POST",

                endpoint="/qa/test-resource",

                status_code=201,

                passed=True,

                response_time_ms=int(
                    post_time
                ),

                message=(
                    "Temporary QA resource created."
                ),
            )
        )

    except Exception as exc:

        db.rollback()

        steps.append(
            QATestStepResponse(

                method="POST",

                endpoint="/qa/test-resource",

                status_code=500,

                passed=False,

                response_time_ms=None,

                message=(
                    "Unable to create temporary "
                    f"QA resource: {exc}"
                ),
            )
        )

        # No resource exists, so continue to summary.
        passed_tests = 0
        failed_tests = 1

        overall_status = "FAIL"

        record = QARecord(
            user_id=current_user.id,
            test_type="api",
            target=target,
            method="CRUD",
            request_body=json.dumps(
                {
                    "workflow": [
                        "POST",
                        "PUT",
                        "GET",
                        "DELETE",
                    ]
                }
            ),
            response_body=json.dumps(
                {
                    "overall_status":
                        overall_status,

                    "steps": [
                        step.model_dump()
                        for step in steps
                    ],
                }
            ),
            status_code=500,
            response_time_ms=0,
        )

        db.add(record)

        db.commit()

        update_assessment_qa(
            db=db,
            current_user=current_user,
            target=target,
            score=0,
        )

        return QAFullAPITestResponse(

            target=target,

            total_tests=1,

            passed_tests=passed_tests,

            failed_tests=failed_tests,

            overall_status=overall_status,

            steps=steps,
        )

    # ==================================================
    # PUT
    # ==================================================

    started = time.perf_counter()

    try:

        resource.name = (
            resource.name
            + " Updated"
        )

        resource.description = (
            "Temporary QA resource updated."
        )

        db.commit()

        db.refresh(resource)

        put_time = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        put_passed = (
            resource.name.endswith(
                " Updated"
            )
        )

        steps.append(
            QATestStepResponse(

                method="PUT",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=(
                    200
                    if put_passed
                    else 500
                ),

                passed=put_passed,

                response_time_ms=int(
                    put_time
                ),

                message=(
                    "Temporary QA resource updated."
                    if put_passed
                    else
                    "Temporary QA resource update failed."
                ),
            )
        )

    except Exception as exc:

        db.rollback()

        steps.append(
            QATestStepResponse(

                method="PUT",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=500,

                passed=False,

                response_time_ms=None,

                message=(
                    "Unable to update temporary "
                    f"QA resource: {exc}"
                ),
            )
        )

    # ==================================================
    # GET
    # ==================================================

    started = time.perf_counter()

    try:

        checked = (
            db.query(
                QATestResource
            )
            .filter(
                QATestResource.id
                == resource.id,

                QATestResource.user_id
                == current_user.id,
            )
            .first()
        )

        get_time = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        get_passed = (
            checked is not None
            and checked.name.endswith(
                " Updated"
            )
        )

        steps.append(
            QATestStepResponse(

                method="GET",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=(
                    200
                    if get_passed
                    else 404
                ),

                passed=get_passed,

                response_time_ms=int(
                    get_time
                ),

                message=(
                    "Updated resource verified successfully."
                    if get_passed
                    else
                    "Updated resource could not be verified."
                ),
            )
        )

    except Exception as exc:

        steps.append(
            QATestStepResponse(

                method="GET",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=500,

                passed=False,

                response_time_ms=None,

                message=(
                    "Unable to verify QA resource: "
                    f"{exc}"
                ),
            )
        )

    # ==================================================
    # DELETE
    # ==================================================

    started = time.perf_counter()

    try:

        db.delete(resource)

        db.commit()

        delete_time = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

        steps.append(
            QATestStepResponse(

                method="DELETE",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=204,

                passed=True,

                response_time_ms=int(
                    delete_time
                ),

                message=(
                    "Temporary QA resource deleted."
                ),
            )
        )

    except Exception as exc:

        db.rollback()

        steps.append(
            QATestStepResponse(

                method="DELETE",

                endpoint=(
                    "/qa/test-resource/"
                    f"{resource.id}"
                ),

                status_code=500,

                passed=False,

                response_time_ms=None,

                message=(
                    "Unable to delete temporary "
                    f"QA resource: {exc}"
                ),
            )
        )

    # ==================================================
    # FINAL RESULT
    # ==================================================

    passed_tests = sum(
        1
        for step in steps
        if step.passed
    )

    failed_tests = (
        len(steps)
        - passed_tests
    )

    overall_status = (
        "PASS"
        if failed_tests == 0
        else
        "FAIL"
    )

    api_score = (
        round(
            (
                passed_tests
                / len(steps)
            )
            * 100
        )
        if steps
        else 0
    )

    # ==================================================
    # SAVE QA RECORD
    # ==================================================

    record = QARecord(

        user_id=current_user.id,

        test_type="api",

        target=target,

        method="CRUD",

        request_body=json.dumps(
            {
                "workflow": [
                    "POST",
                    "PUT",
                    "GET",
                    "DELETE",
                ]
            }
        ),

        response_body=json.dumps(
            {
                "overall_status":
                    overall_status,

                "steps": [
                    step.model_dump()
                    for step in steps
                ],
            }
        ),

        status_code=(
            200
            if failed_tests == 0
            else 500
        ),

        response_time_ms=sum(
            step.response_time_ms or 0
            for step in steps
        ),
    )

    db.add(record)

    db.commit()

    # ==================================================
    # UPDATE ASSESSMENT
    # ==================================================

    update_assessment_qa(
        db=db,

        current_user=current_user,

        target=target,

        score=api_score,
    )

    return QAFullAPITestResponse(

        target=target,

        total_tests=len(steps),

        passed_tests=passed_tests,

        failed_tests=failed_tests,

        overall_status=overall_status,

        steps=steps,
    )


# ==================================================
# EXISTING UI / UX SAVE
# ==================================================

@router.post(
    "/uiux",
    response_model=QARecordResponse,
)
def save_uiux_review(
    payload: QAUISaveRequest,

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    record = QARecord(

        user_id=current_user.id,

        test_type="uiux",

        target=payload.target,

        responsive=payload.responsive,

        navigation=payload.navigation,

        accessibility=payload.accessibility,

        performance=payload.performance,

        visual_consistency=payload.visual_consistency,

        uiux_score=payload.uiux_score,

        review_notes=payload.review_notes,
    )

    db.add(record)

    db.commit()

    db.refresh(record)

    # Update assessment with manual/human UIUX score.
    update_assessment_qa(
        db=db,

        current_user=current_user,

        target=payload.target or "",

        score=payload.uiux_score,
    )

    return record


# ==================================================
# MARKET ANALYSIS
# ==================================================

@router.post(
    "/market",
    response_model=QARecordResponse,
)
def save_market_analysis(
    payload: QAMarketSaveRequest,

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    record = QARecord(

        user_id=current_user.id,

        test_type="market",

        target=payload.target,

        product=payload.product,

        industry=payload.industry,

        competitor=payload.competitor,

        analysis_focus=payload.analysis_focus,

        market_notes=payload.market_notes,
    )

    db.add(record)

    db.commit()

    db.refresh(record)

    return record


# ==================================================
# MANUAL API TESTING
# ==================================================

@router.post(
    "/api-test",
    response_model=QARecordResponse,
)
def run_api_test(
    payload: QAAPIRequest,

    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    method = payload.method.upper()

    validate_target_endpoint(
        payload.target,
        payload.endpoint_url,
    )

    if method not in {
        "GET",
        "POST",
        "PUT",
        "DELETE",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only GET, POST, PUT and DELETE "
                "are supported."
            ),
        )

    request_body = None

    if method != "GET":

        if payload.request_body is None:

            raise HTTPException(
                status_code=400,
                detail=(
                    f"{method} requests require "
                    "a JSON request body."
                ),
            )

        request_body = payload.request_body

    started = time.perf_counter()

    try:

        with httpx.Client(
            timeout=httpx.Timeout(15.0),
            follow_redirects=False,
            headers={
                "Accept": (
                    "application/json,"
                    "text/plain,"
                    "*/*"
                ),
                "User-Agent":
                    "SOC-Platform-QA/1.0",
            },
        ) as client:

            response = client.request(

                method,

                payload.endpoint_url,

                json=request_body,
            )

        response_time_ms = round(
            (
                time.perf_counter()
                - started
            )
            * 1000,
            2,
        )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail=(
                "Target request timed out "
                "after 15 seconds."
            ),
        )

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                "Unable to reach target endpoint: "
                f"{exc}"
            ),
        )

    response_text = (
        response.text[:12000]
    )

    request_body_text = (
        json.dumps(
            request_body
        )
        if request_body is not None
        else None
    )

    record = QARecord(

        user_id=current_user.id,

        test_type="api",

        target=payload.target,

        method=method,

        request_body=request_body_text,

        response_body=response_text,

        status_code=response.status_code,

        response_time_ms=int(
            response_time_ms
        ),
    )

    db.add(record)

    db.commit()

    db.refresh(record)

    # ----------------------------------------------
    # Update Assessment
    # ----------------------------------------------

    manual_score = (
        100
        if 200 <= response.status_code < 400
        else 0
    )

    update_assessment_qa(
        db=db,

        current_user=current_user,

        target=payload.target,

        score=manual_score,
    )

    return record


# ==================================================
# QA HISTORY
# ==================================================

@router.get(
    "/history",
    response_model=list[QARecordResponse],
)
def get_qa_history(
    current_user: User = Depends(
        require_role(1)
    ),

    db: Session = Depends(get_db),
):
    records = (
        db.query(QARecord)

        .filter(
            QARecord.user_id
            == current_user.id
        )

        .order_by(
            QARecord.created_at.desc()
        )

        .all()
    )

    return records