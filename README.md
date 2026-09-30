# grok-sandbox-analysis

Notes et findings sur l'environnement d'exécution de Grok (la feature "Computer"), sur laquelle j'ai passé pas mal de temps en septembre 2026. En gros c'est un container root dans une VM jetable par session, et j'ai voulu cartographier ce qui tient et ce qui casse une fois qu'on est dedans.

## C'est quoi ce repo

Du recon et du test manuel fait depuis des sessions Grok actives. Rien d'automatisé, juste de l'exploration : privilèges, isolation, réseau, persistence, la surface KVM, et surtout la piste kernel (CVE-2026-53361 / BadGarbage) qui est la seule qui menace vraiment la frontière container → VM.

## Contenu

- **[FINDINGS.md](FINDINGS.md)** — le rapport complet. Architecture, findings triés par sévérité, la chaîne d'attaque réaliste (JWT + mémoire + tool server), le détail sur BadGarbage, et les recos côté défense.

## Le résumé en trois lignes

- L'isolation cross-user / cross-chat tient bien : VMs séparées, artifacts scopés par conversation, pas d'impact cross-user démontré.
- En intra-session par contre c'est root + presque toutes les caps, un tool server local sans auth, et des secrets de session (JWT) lisibles par tout le monde. Hijack de session trivial.
- Le kernel (6.12.8+) est dans la fenêtre vulnérable de BadGarbage. L'UAF est reachable, l'escape complet non abouti sur ce build (pas de BTF/vmlinux pour retarget les offsets), mais le risque résiduel reste critique tant que c'est pas patché en 6.12.95+.

## Contexte / disclaimer

Recherche menée sur mes propres sessions, à but défensif et d'apprentissage. Rien ici ne vise d'autres utilisateurs — l'isolation cross-tenant n'a d'ailleurs jamais été franchie dans mes tests. Les recos en fin de rapport sont là pour que ça se corrige côté plateforme.
