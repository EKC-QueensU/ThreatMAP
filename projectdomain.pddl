(define (domain project)

    (:requirements :conditional-effects :negative-preconditions :equality :adl :typing :non-deterministic)


    (:types
        state attacker user network computer software
    )


    (:predicates ; to implement computers/states
        (at ?x - state)
        (link ?x ?y)
        (has_root ?x - attacker ?y - user) ; Updated from (has_root ?x)
        (network_scanned ?x  - network)
        (knows_account ?x - attacker ?y - user) ; User account is known, before credentials are gotten
        (has_credential ?x - attacker ?y - user)
        (has_vulnerability ?x - computer)
        (c2_active ?x - software ) ;Updated from (c2_active ?x)
        (unsecured_credentials ?x - attacker ?y - user ?c - computer ) ; Allows to state that the credentials are stored plaintext, in registry, etc
        (knows_user ?a - attacker ?u - user) ; Updated from (knows_user ?a - attacker ?u - user)
        (has_user ?x)
        (computerscanned ?x)
        (has_file ?x)
        (has_data ?x) 
        (has_software ?x)
        (has_account ?x)
        (has_access ?x)
        (is_exploitable ?x)

        (has_privilege ?x)
        (has_permission ?x)
        (has_group ?x)
        (has_service ?x)
        
        (empty_network ?x) ; Remove as discussed?
        (installed ?x - software)

    )

    ; Phishing
    (:action t1598
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - state 
            ?s2 - state)
        :precondition (and 
            (at ?s1)
            (not (knows_user ?a ?u))
            (link ?s1 ?s2)
        
        )
        :effect (and 
                    (oneof 
                        ; Phishing successful 
                        (and
                            (not (at ?s1))
                            (at ?s2)
                            (knows_user ?a ?u)
                        )
                        ; Phishing not successful
                        (at ?s1)
                    )
                )
    )

    ; Compromised Accounts
    (:action t1586
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer 
            ?s1 - state 
            ?s2 - state)
        :precondition (
            and 
                (knows_user ?a ?u)
                (at ?s1)
                (link ?s1 ?s2)
                (not (at ?s2))
                (not (has_credential ?a ?u))
                (not (unsecured_credentials ?a ?u ?c))
        )
        :effect (and 
                    (oneof
                            ; Credentials aren't stored securely (accessed on computer)
                            (unsecured_credentials ?a ?u ?c) 
                            ;Credentials are found on password list
                            (has_credential ?a ?u )               
                    )
                    (not (at ?s1))
                    (at ?s2)
                )      
    )


    ; Valid account
    (:action t1078
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer 
            ?s1 - state 
            ?s2 - state)
        :precondition (and 
            ; (at ?s1) ; error fond problem
            (link ?s1 ?s2)
            (or
                (has_credential ?a ?u )
                (unsecured_credentials ?a ?u ?c)
            )
            (not (has_root ?a ?u))
        )
        :effect (and 
                ; gain root access
                (has_root ?a ?u)
                (not (at ?s1))
                (at ?s2)
        )
    )


    ; Scheduled task
    (:action t1053
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer 
            ?s1 - state 
            ?s2 - state
            ?i - software
        )
        :precondition (and
            (link ?s1 ?s2)
            (at ?s1)
            (has_root ?a ?u)
        )

        :effect (and 
            (oneof
                (when (installed ?i) (c2_active ?i))
                (when (has_root ?a ?u) (installed ?i))
            )
            (not (at ?s1))
            (at ?s2)
        )
    )

    ; Encrypted channel
    (:action t1573
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer 
            ?s1 - state
            ?s2 - state
            ?i - software)
        :precondition (and
            (at ?s1) 
            (has_root ?a ?u) 
            (c2_active ?c)
            (link ?s1 ?s2)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
        )
    )


; To fix or implement ------------------------------------------------------------------------


    ; Data from local system
    ; (:action t1005
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (c2_active ?x)
    ;         (has_root ?x)
    ;         ; Does this need to be different? (can't have oneof in precondition)
    ;         (oneof 
    ;             (has_data ?x)
    ;             (has_file ?x)
    ;         )
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
    ;         (not (at ?x))
    ;         (at ?y)
    ;     )
    ; )

    ; Network sniffing
    ; (:action t1040
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         ; must have root to sniff network
    ;         (has_root ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
    ;         (network_scanned ?y)
    ;         (oneof 
    ;             (has_vulnerability ?y)
    ;             (has_service ?y)
    ;             (empty_network ?y) ; is this needed?
    ;         )
    ;         (not (at ?x))
    ;         (at ?y)
    ;         (has_root ?y)
    ;     )
    ; )

    ;  Process injection
    ; (:action t1055
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_vulnerability ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
    ;         (has_root ?y)
    ;         (not (at ?x))
    ;         (at ?y)
    ;     )
    ; )

    ; File and directory discovery
    ; (:action t1083
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_root ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
        
    ;         ; update attacker
    ;         (has_data ?y)
    ;         (has_file ?y)

    ;         ; move state
    ;         (not (at ?x))
    ;         (at ?y)
        
    ;     )
    ; )

    ; Account Discovery
    ; (:action t1087
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_root ?x)
    ;         (link ?x ?y)
        
    ;     )
    ;     :effect (and 
    ;         (has_user ?y)
    ;         (has_group ?y)
    ;         (not (at ?x))
    ;         (at ?y)
    ;     )
    ; )

    ; MFA Intercept
    ; (:action t1111
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_access ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
    ;         (has_credential ?y)
    ;         (not (at ?x))
    ;         (at ?y)
    ;     )
    ; )

    ; Explot of client execution
    ; (:action t1203
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_vulnerability ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and 
    ;         (has_root ?y)
    ;         (not (at ?x))
    ;         (at ?y)
    ;     )
    ; )

    ;  Steal application access token
    ; (:action t1528
    ;     :parameters (?x ?y)
    ;     :precondition (and 
    ;         (has_root ?x)
    ;         (link ?x ?y)
    ;     )
    ;     :effect (and
    ;         (has_credential ?y) ;Access or credentials?
    ;         (has_root ?y)
    ;         (not (at ?x))
    ;         (at ?y)
        
    ;     )
    ; )

    ; Internal spearphishing
    ; (:action t1534
    ;     :parameters (?u1 ?u2 - user ?a - attacker ?s1 ?s2 - state)
    ;     :precondition (and 
    ;         (has_credential ?a ?u1)
    ;         (link ?s1 ?s2))
    ;     :effect (and 
    ;         (has_credential ?a ?u2)
    ;         (not (at ?s1))
    ;         (at ?s2)
    ;     )
    ; )

    ; Unsecured credentials
    ; (:action t1552
    ;     :parameters (?u - user ?a - attacker ?c - computer ?s1 ?s2 - state)
    ;     :precondition (oneof
    ;                         (unsecured_credentials ?a ?u ?c)
    ;                         (has_credential ?a ?u )
    ;                   )
    ;     :effect (and 
    ;                 (not (at ?x))
    ;                 (at ?y)
    ;             )
    ; )

    ; Compromised Accounts
    ; (:action t1586
    ;     :parameters (?u - user ?a - attacker ?c - computer ?s1 ?s2 - state)
    ;     :precondition (knows_user ?a ?u)
    ;     :effect (and (oneof
    ;                         ; Credentials aren't stored securely (accessed on computer)
    ;                         (and
    ;                             (unsecured_credentials ?a ?u ?c) ; PREDICATE NEEDS TO BE ADDED TO SCANNING
    ;                             (not (at ?x))
    ;                             (at ?y)
    ;                         )
    ;                         ; Credentials are found on password list
    ;                         (and
    ;                             (has_credential ?a ?u )
    ;                             (not (at ?x))
    ;                             (at ?y))
    ;                  )
    ;             )      
    ; )


)
