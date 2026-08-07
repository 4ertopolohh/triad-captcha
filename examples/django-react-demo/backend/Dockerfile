FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN addgroup --system app && adduser --system --ingroup app app
WORKDIR /app

COPY packages/django /build/triadcaptcha-django
COPY examples/django-react-demo/backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install /build/triadcaptcha-django \
    && python -m pip install -r /tmp/requirements.txt \
    && rm -rf /build /tmp/requirements.txt

COPY examples/django-react-demo/backend /app
RUN chown -R app:app /app
USER app

EXPOSE 8000
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py bootstrap_triadcaptcha --actions register login lead && python manage.py collectstatic --noinput && exec gunicorn demo_project.wsgi:application --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 30"]
