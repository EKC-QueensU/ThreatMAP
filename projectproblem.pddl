(define (problem project)
    (:domain project)
    (:objects
        reconnaissance - state
        resource_development - state
        credential_access - state
        initial_access - state
        lateral_movement - state
        privilege_escalation - state
        discovery - state
        execution - state
        persistence - state
        collection - state
        command_and_control - state
        impact - state
        exfiltration - state
        attacker_01 - attacker
        user_acct_01 - user
        computer_01 - computer
        network_01 - network
        expliot - software
    )


    (:init
        ; kill chain first demo
        (at reconnaissance)
        (link reconnaissance resource_development)
        (link resource_development initial_access)
        (link initial_access privilege_escalation)
        (link privilege_escalation persistence)
        (link persistence command_and_control)
        (link command_and_control exfiltration)
        ; -----------------------

        (link credential_access initial_access)
        (link credential_access discovery)
        (link credential_access lateral_movement)
        (link credential_access persistence)
        (link discovery resource_development)
        (link discovery discovery)   
        (link privilege_escalation execution)
        (link privilege_escalation credential_access)
        (link lateral_movement discovery)
        (link execution execution)
        (link execution privilege_escalation)
        (link persistence resource_development)
        (link command_and_control collection)
        (link collection impact)
        (link collection exfiltration)
    )

    (:goal (and
                (at exfiltration)
                (at impact)
            )
    )

)
