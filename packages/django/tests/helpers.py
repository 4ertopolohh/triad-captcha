from __future__ import annotations

from altcha import Challenge, Payload, solve_challenge

from triadcaptcha_django.models import ProtectedAction


def issue_and_solve(client, settings, *, action="register", identity="one@example.test"):
    policy = ProtectedAction.objects.get(action=action)
    if policy.base_risk_score < policy.challenge_threshold:
        policy.base_risk_score = policy.challenge_threshold
        policy.save(update_fields=("base_risk_score",))
    protected_headers = {
        "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
        "X-TriadCAPTCHA-Action": action,
    }
    initial = client.post(
        "/protected/",
        data={"email": identity},
        content_type="application/json",
        headers=protected_headers,
    )
    assert initial.status_code == 428, initial.content
    attempt = initial.json()["error"]["attempt"]
    response = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": action},
        headers={
            **protected_headers,
            "X-TriadCAPTCHA-Attempt": attempt,
        },
    )
    assert response.status_code == 200, response.content
    challenge = Challenge.from_dict(response.json()["challenge"])
    solution = solve_challenge(challenge, timeout=3)
    assert solution is not None
    return response, Payload(challenge, solution).to_base64(), attempt
