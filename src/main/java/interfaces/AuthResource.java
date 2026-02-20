package interfaces;

import java.time.Instant;
import java.util.Set;

import application.UsuarioService;
import application.representation.UsuarioRepresentation;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

@Path("/auth")
public class AuthResource {

    @Inject
    private UsuarioService usuarioService;

    @GET
    @Path("/token")
    public TokenResponse token(
            @QueryParam("user") String user,
            @QueryParam("password") String password,
            @QueryParam("rol") String rol) {

        // Aqui es donde se compara el password y usuario contra la base
        UsuarioRepresentation usuario = usuarioService.findByUsuario(user);
        // TAREA
        boolean ok = false;
        // String rol = null;
        
        if (usuario != null && usuario.getPassword().equals(password)) {
            ok = true;
            rol = usuario.getRol();
        }

        if (ok) {
            String issuer = "concesionaria-auth";
            
            // 2. Usamos el valor recibido. Si viene nulo o es 0, usamos 8000 por defecto.
            // long ttl = (tiempoVigencia != null && tiempoVigencia > 0) ? tiempoVigencia : 8000;
            long ttl = 8000;

            Instant now = Instant.now();
            Instant exp = now.plusSeconds(ttl);

            String jwt = Jwt.issuer(issuer)
                    .subject(user)
                    .groups(Set.of(rol)) // roles: user / admin
                    .issuedAt(now)
                    .expiresAt(exp)
                    .sign();

            return new TokenResponse(jwt, exp.getEpochSecond(), rol);
        } else {
            return null;
        }
    }

    public static class TokenResponse {
        public String accessToken;
        public long expiresAt;
        public String rol;

        public TokenResponse() {
        }

        public TokenResponse(String accessToken, long expiresAt, String role) {
            this.accessToken = accessToken;
            this.expiresAt = expiresAt;
            this.rol = role;
        }
    }

}