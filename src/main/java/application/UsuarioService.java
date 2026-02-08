package application;

import java.util.List;

import application.representation.UsuarioRepresentation;
import domain.Usuario;
import infraestructure.UsuarioRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class UsuarioService {

    @Inject
    private UsuarioRepository usuarioRepository;

    public List<Usuario> listarTodos() {
        return this.usuarioRepository.listAll();
    }

    public UsuarioRepresentation findByUsuario(String user) {
        return this.mapperToUR(this.usuarioRepository.find("usuario", user).firstResult());
    }

    private UsuarioRepresentation mapperToUR(Usuario usuario){
        UsuarioRepresentation ur = new UsuarioRepresentation();
        ur.setUsuario(usuario.getUsuario());
        ur.setPassword(usuario.getPassword());
        ur.setRol(usuario.getRol());
        return ur;
    }
}
