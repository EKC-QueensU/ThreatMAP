(define (problem mitreattack)
    (:domain mitreattack)
    (:objects
        ; 7 states
        recon - reconnaissance
        res_dev - resource_development
        init_access - initial_access
        exe - exploitation
        pers - exploitation
        priv_esc - installation
        cred_access - installation
        disc - installation
        lat_mov - command_and_control
        col - command_and_control
        cc - command_and_control
        goal - act_on_objective
        
        ; entities -  Can be changed dependant on enterprise network
        attacker_01 - attacker
        user_acct_01 - user
        computer_01 - computer
        network_01 - network
        exploit - software
        domain_01 - network_domain
        exploit_01 - exploit


    )

    (:init
        ; Never changes
        (at recon)
    )

    ; Instructions for testing kill chains:
    ;   1. Uncomment the observations for the kill chain you want to test. Only 1 kill chain can be run at a time
    ;   2. Comment out the observations for the other kill chains
    ;   3. Run the planner - LAMA in planutils enviroment (lama finaldomain.pddl finalproblem.pddl)
    ; You may add your own kill chains and determine if they are detectable 

    (:goal (and
                ; Never changes
                (at goal)

                ; list of observed predicates
                ; Observations Kill Chain 1 (Ferocious Kitten)
                (unsecured_credentials attacker_01 user_acct_01 computer_01) 
                (been_spearphished user_acct_01)
                (is_exploitable computer_01)
                (gained_persistence attacker_01 computer_01)

                ; ; Obervatations Kill Chain 2 (APT29)
                ; (installed_tools attacker_01 computer_01)
                ; (gained_persistence attacker_01 computer_01)

                ; ;Obervatations Kill Chain 3 (APT29)
                ; (gained_persistence attacker_01 computer_01)
                ; (exploit_installed exploit_01 computer_01)


                ; ;Obervatations Kill Chain 4 (Axiom)
                ; (network_scanned network_01)
                ; (in_botnet computer_01)
                ; (malware_running computer_01)
                ; (has_data computer_01)


                ;Obervatations Kill Chain 5 (Metador)
                ; (installed_tools attacker_01 computer_01)
                ; (has_system_access attacker_01 computer_01)
                ; (installed_tools attacker_01 computer_01)






            )
    )


)
