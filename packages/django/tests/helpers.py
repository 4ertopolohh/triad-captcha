from __future__ import annotations

from altcha import Challenge, Payload, solve_challenge


def issue_and_solve(client, settings, *, action="register"):
    response = client.get(
        "/api/triadcaptcha/challenge/",
        {"action": action},
        headers={
            "X-TriadCAPTCHA-Site-Key": settings.TRIADCAPTCHA_SITE_KEY,
            "X-TriadCAPTCHA-Action": action,
        },
    )
    assert response.status_code == 200, response.content
    challenge = Challenge.from_dict(response.json()["challenge"])
    solution = solve_challenge(challenge, timeout=3)
    assert solution is not None
    return response, Payload(challenge, solution).to_base64()
