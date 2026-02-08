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
            @QueryParam("password") String password) {

        // Aqui es donde se compara el password y usuario contra la base
        UsuarioRepresentation usuario = usuarioService.findByUsuario(user);
        // TAREA
        boolean ok = false;
        String rol = null;
        
        if (usuario != null && usuario.getPassword().equals(password)) {
            ok = true;
            rol = usuario.getRol();
        }

        if (ok) {
            String issuer = "vuelo-auth";
            long ttl = 3600;

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