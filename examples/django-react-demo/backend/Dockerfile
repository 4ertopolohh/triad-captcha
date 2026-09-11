FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup --system app && adduser --system --ingroup app app
WORKDIR /app

COPY packages/django /build/triadcaptcha-django
COPY examples/django-react-demo/backend/requirements.lock /tmp/requirements.lock
RUN python -m pip install --require-hashes -r /tmp/requirements.lock \
    && python -m pip install --no-deps --no-build-isolation /build/triadcaptcha-django \
    && rm -rf /build /tmp/requirements.lock

COPY examples/django-react-demo/backend /app
RUN chown -R app:app /app
USER app

EXPOSE 8000
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py bootstrap_triadcaptcha --actions register login lead && python manage.py check_triadcaptcha_production && python manage.py collectstatic --noinput && exec gunicorn demo_project.wsgi:application --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 30"]
