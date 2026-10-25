FROM node:22-alpine
WORKDIR /app
COPY server.js package.json ./
COPY index.html ./
ENV PORT=8080
EXPOSE 8080
CMD ["node","server.js"]
