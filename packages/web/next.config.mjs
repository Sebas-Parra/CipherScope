/** @type {import('next').NextConfig} */
const nextConfig = {
  // El core es un paquete del workspace; que Next lo transpile.
  transpilePackages: ["@cipherscope/core"],
};

export default nextConfig;
