FROM node:22-alpine AS frontend
WORKDIR /src
COPY packages/react/package*.json packages/react/
# The package has a `prepare` lifecycle that needs source files. Keep the
# dependency-cache layer source-independent and build explicitly after COPY.
RUN npm --prefix packages/react ci --ignore-scripts
COPY packages/react packages/react
RUN npm --prefix packages/react run build
COPY examples/django-react-demo/frontend/package*.json examples/django-react-demo/frontend/
RUN npm --prefix examples/django-react-demo/frontend ci
COPY examples/django-react-demo/frontend examples/django-react-demo/frontend
ARG VITE_TRIADCAPTCHA_SITE_KEY
ENV VITE_TRIADCAPTCHA_SITE_KEY=${VITE_TRIADCAPTCHA_SITE_KEY}
RUN npm --prefix examples/django-react-demo/frontend run build

FROM nginx:1.28-alpine
COPY infra/nginx/nginx.conf /etc/nginx/nginx.conf
COPY infra/nginx/http-rate-limits.conf /etc/nginx/snippets/http-rate-limits.conf
COPY infra/nginx/triadcaptcha-locations.conf /etc/nginx/snippets/triadcaptcha-locations.conf
COPY --from=frontend /src/examples/django-react-demo/frontend/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
