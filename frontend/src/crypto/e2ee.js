// O núcleo E2EE do projeto (shared/e2ee), SEM cópia nem alteração: o alias
// @e2ee do Vite aponta para ../shared/e2ee (vite.config.js). Todo o frontend
// importa daqui.
import e2ee from "@e2ee/index.js";

export default e2ee;
