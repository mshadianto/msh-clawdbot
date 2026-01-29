FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Create logs directory
RUN mkdir -p /app/logs && chown -R nodejs:nodejs /app

# Copy package files
COPY --chown=nodejs:nodejs package*.json ./

# Install pnpm & dependencies
RUN npm install -g pnpm && \
    pnpm install --frozen-lockfile

# Copy source code
COPY --chown=nodejs:nodejs index-secure.js ./

# Switch to non-root user
USER nodejs

EXPOSE 3001

CMD ["node", "index-secure.js"]
