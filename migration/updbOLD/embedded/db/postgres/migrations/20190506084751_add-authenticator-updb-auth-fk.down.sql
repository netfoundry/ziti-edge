alter table ziti_edge.authenticator_updbs
    add column identity_id uuid;

alter table ziti_edge.authenticator_updbs
    add constraint identity_id__fk
        foreign key (identity_id) references ziti_edge.identities;


-- move identity_id back to authenticator_updbs
update ziti_edge.authenticator_updbs au
set identity_id = (select a.identity_id from ziti_edge.authenticators a where a.id = au.authenticator_id)
where 1 = 1;

alter table ziti_edge.authenticator_updbs
    alter column identity_id set not null;

alter table ziti_edge.authenticator_updbs
    drop column authenticator_id;

delete
from ziti_edge.authenticators
where method = 'updb';