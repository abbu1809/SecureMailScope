# Stage 1: Build Frontend Assets
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies first for efficient caching
COPY package.json package-lock.json* ./
RUN npm ci

# Copy source code and build
COPY . .

# Build Vite application for production
# In containerized/reverse-proxy setup, VITE_API_BASE defaults to /api
ARG VITE_API_BASE=/api
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled assets from builder
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
