(define (domain mitreattack)

    (:requirements :conditional-effects :negative-preconditions :equality :adl :typing)


    ; This is the project file for the ThreatMAP
    ; There are 5 different APTs within this file
    ; Some actions are shared amoung the APTs.



    (:types
        ; entities
        attacker 
        user 
        network 
        network_domain
        computer 
        software 
        token
        exploit

        ; stages
        reconnaissance 
        resource_development
        initial_access 
        exploitation
        installation
        command_and_control 
        act_on_objective
    )


    (:predicates 
        ;  Used for movements between stages
        (at ?s)
        
        ; Predicates to describe the state of the cyber kill chain
        (has_credential ?x - attacker ?y - user) ; Attacker has credentials
        (acquire_domain ?a - attacker ?d - network_domain) ; A domain infrastructure was obtained by the attacker
        (unsecured_credentials ?a - attacker ?u - user ?c - computer ) ; Allows to state that the credentials are stored plaintext, in registry, etc
        (knows_user ?a - attacker ?u - user) ; Attacker knows user account
        (is_exploitable ?c - computer) ; Denotes if a computer can be exploited
        (been_spearphished ?u - user) ; Denotes if a user has been spearphished
        (gained_persistence ?a - attacker ?c - computer) ; Attacker has gained persistance on a computer 
        (is_root ?u - user ?a - attacker) ; Attacker has gained root priviledges for a user
        (has_vulnerability ?c - computer) ; Denotes if a computer is vulnerable (Different from being exploitable, vulnerability must be used first)
        (has_system_access ?a - attacker ?c - computer) ; Attacker has access to system (all files/services on a computer)
        (has_data ?c - computer) ; Collect data from a computer 
        (installed_tools ?a - attacker ?c - computer) ; Attacker installed tools to enable attack
        (been_exploited ?a - attacker ?c - computer) ; Computer has been exploited by attacker
        (exploit_installed ?e - exploit ?c - computer) ; Exploit is installed on a computer 
        (c2_channel ?c - computer) ; Computer has a C2 (communication) channel
        (is_user ?u - user) ; Attacker is the user
        (setup_dns ?c - computer) ; Attacker DNS is set up 
        (payload_encrypted ?c - computer) ; Attack payload is encypted 
        (in_botnet ?c - computer) ; Computer becomes part of botnet
        (network_scanned ?n - network) ; Enterprise network has been scanned
        (malware_running ?c - computer) ; Malware is running on a computer
        (laterally_moved ?a - attacker ?u - user) ; The attacker was able to laterally move on the network
    )

; Ferocious Kitten

    ; Phishing For Information - Recon
    (:action t1598
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - reconnaissance 
            ?s2 - resource_development
        )
        :precondition (and 
            (at ?s1)
            
        )
        :effect (and 
                ; Phishing successful 
                (not (at ?s1))
                (at ?s2)
                (knows_user ?a ?u)
            )
        )


    ; Compromised Accounts - Resource Dev
    (:action t1586
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer 
            ?s1 - resource_development 
            ?s2 - initial_access
            )
        :precondition (
            and 
                (knows_user ?a ?u)
                (at ?s1)
            )
        :effect (and 
                (not (at ?s1))
                (at ?s2)
                ; Credentials aren't stored securely (accessed on computer)
                (unsecured_credentials ?a ?u ?c)           
                )      
    )

    ; Phishing: Spearphishing Attachment - Initial Access 
    (:action t1566_001
        :parameters (
            ?a - attacker
            ?u - user 
            ?c - computer
            ?s1 - initial_access
            ?s2 - exploitation
        )
        :precondition (and 
            (at ?s1) 
            (unsecured_credentials ?a ?u ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (been_spearphished ?u)
        )
    )

    ; User Execution: Malicious File - - Execution -NO also
    (:action t1204.002
        :parameters (
            ?a - attacker
            ?u - user
            ?c - computer
            ?s1 - exploitation
            ?s2 - installation 

        )
        :precondition (and
            (at ?s1) 
            (been_spearphished ?u)
            )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (is_exploitable ?c)
        )
    )
    ; Exploitation for Privilege Escalation - Privlege Escalation 
    (:action t1068
        :parameters (
            ?a - attacker 
            ?c - computer 
            ?s1 - installation 
            ?s2 - command_and_control
        )
        :precondition (and
                (at ?s1)
                (is_exploitable ?c)
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (gained_persistence ?a ?c)
            )
    
    )
    ; Ingress Tool Transfer - Command and Control (APT29)
    (:action t1105
        :parameters (
            ?a - attacker
            ?u - user
            ?c - computer
            ?s - software
            ?s1 - command_and_control
            ?s2 - act_on_objective
        )
        :precondition (and
            (at ?s1) 
            (gained_persistence ?a ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
        )
    )

; APT29

    ; T1589.001 Gather Victim Identity Information: Credentials - Recon
    (:action t1589_001
        :parameters (
            ?u - user 
            ?a - attacker  
            ?s1 - reconnaissance
            ?s2 - resource_development
        )
        :precondition (and 
            (at ?s1) 
        )
        :effect (and 
                (not (at ?s1))
                (at ?s2)
                (has_credential ?a ?u )
        )
    )

    ; T1583_006 Acquire Infrastructure: Domains - Resource Dev
    (:action t1583_001
        :parameters (
            ?d - network_domain
            ?a - attacker
            ?u - user
            ?s1 - resource_development
            ?s2 - initial_access
        )
        :precondition (and 
            (at ?s1) 
            (has_credential ?a ?u )
            )
        :effect (and 
            (acquire_domain ?a ?d)
            (not (at ?s1))
            (at ?s2))
    )

    ; t1078 Valid account - Initial Access 
    (:action t1078
        :parameters (
            ?u - user 
            ?a - attacker 
            ?c - computer
            ?d - network_domain
            ?s1 - initial_access
            ?s2 - exploitation
        )
        :precondition (and 
            (at ?s1) 
            (has_credential ?a ?u )
            (acquire_domain ?a ?d)
        )
        :effect (and 
                (not (at ?s1))
                (at ?s2)
                ; Has system access
                (has_system_access ?a ?c)
        )
    )
    ; t1059.003 Command and Scripting Interpreter: Windows Command Shell - Execution
    (:action t1059_003
        :parameters ( 
            ?a - attacker 
            ?c - computer
            ?s1 - exploitation
            ?s2 - installation
        )
        :precondition (and 
            (at ?s1) 
            (has_system_access ?a ?c)
        )
        :effect (and 
                (not (at ?s1))
                (at ?s2)
                ; Installed tools to exploit system
                (installed_tools ?a ?c)
        )
    )  
    ; t1068 Exploitation for Privilege Escalation - Privlege Escalation 
    (:action t1068
        :parameters (
            ?a - attacker 
            ?c - computer 
            ?s1 - installation 
            ?s2 - command_and_control
        )
        :precondition (and
                (at ?s1)
                (installed_tools ?a ?c)
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (gained_persistence ?a ?c)
            )
    
    )

    ;T1021.001 Remote Services: Remote Desktop Protocol - Lateral Movement
    (:action t1068
        :parameters (
            ?a - attacker 
            ?c - computer 
            ?s1 - command_and_control 
            ?s2 - act_on_objective
        )
        :precondition (and
                (at ?s1)
                (installed_tools ?a ?c)
                (gained_persistence ?a ?c)
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (been_exploited ?a ?c)
            )
    
    )


    ; t1595 Active Scanning: Vulnerability Scanning - Recon
    (:action t1595_002
        :parameters (
            ?a - attacker 
            ?u - user 
            ?c - computer
            ?s1 - reconnaissance
            ?s2 - resource_development
        )
        :precondition (and 
            (at ?s1)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (has_vulnerability ?c)
        )
    )

    ; T1584.001 Compromise Infrastructure: Domains -Resource Development
    (:action t1584_001
        :parameters (
            ?a - attacker 
            ?u - user 
            ?c - computer
            ?s1 - resource_development
            ?s2 - initial_access
        )
        :precondition (and 
            (at ?s1)
            (has_vulnerability ?c) ; Domain Vuln
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (knows_user ?a ?u)
        )
    )


    ; T1547.001 Boot or Logon Autostart Execution: Registry Run Keys - Pers
    (:action t1547_001_Pers
        :parameters (
            ?a - attacker 
            ?u - user 
            ?c - computer
            ?s1 - initial_access
            ?s2 - exploitation
        )
        :precondition (and 
            (at ?s1)
            (knows_user ?a ?u)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (gained_persistence ?a ?c)
        )
    )

    
    ; T1547.001 Boot or Logon Autostart Execution: Registry Run Keys - Priv Esc
    (:action t1547_001_PE
        :parameters (
            ?a - attacker
            ?c - computer
            ?e - exploit
            ?s1 - exploitation
            ?s2 - installation
        )
        :precondition (and 
            (at ?s1)
            (gained_persistence ?a ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (exploit_installed ?e ?c) ; Other than C2 Channel
        )
    )
; T1573 Encrypted Channel - Command & Control 
    (:action t1573
        :parameters (
            ?c - computer
            ?e - exploit
            ?s1 - installation
            ?s2 - command_and_control
        )
        :precondition (and 
            (at ?s1)
            (exploit_installed ?e ?c)
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (c2_channel ?c)
            )
    )

;T1021.006 Remote Services: Windows Remote Management - Lateral Movement
    (:action t1021_006
        :parameters (
            ?a - attacker
            ?c - computer
            ?s1 - installation
            ?s2 - command_and_control
        )
        :precondition (and 
            (at ?s1)
            (c2_channel ?c)
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (been_exploited ?a ?c)
            )
    )

    ;T1102 Web Service: Bidirectional Communication - Command & Control
    (:action t1102
        :parameters (
            ?a - attacker
            ?c - computer
            ?s1 - command_and_control
            ?s2 - act_on_objective
        )
        :precondition (and 
            (at ?s1)
            (c2_channel ?c)
            
        )
        :effect (and
                (not(at ?s1))
                (at ?s2)
                (been_exploited ?a ?c)
            )
    )

; Axiom

    ; Acquire Infrastructure: DNS Server - Resource Development
    (:action t1583_002
        :parameters (
            ?u - user 
            ?c - computer
            ?s1 - resource_development
            ?s2 - initial_access
        )
        :precondition (and
            (at ?s1)
            (is_user ?u)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            
            (setup_dns ?c)
        )
    )


    ; Archive Collected Data - Collection
    (:action t1560
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - collection
            ?s2 - exfiltration
            
        )
        :precondition (and 
            (at ?s1)
            (c2_channel ?c)
            (is_root ?u ?a)
            (has_data ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (payload_encrypted ?c)
        )
    )


    ; Compromise Infrastructure: Botnet - Resource Development 
    (:action t1584_005
        :parameters (
            ?s1 - resource_development
            ?s2 - initial_access
            ?c - computer
            ?n - network
        )
        :precondition (and
            (at ?s1)
            (network_scanned ?n)
            (is_exploitable ?c) ; info attacker would have
        )
        :effect (and 
            (in_botnet ?c)
            (at ?s2)
            (not (at ?s1))
        )
    )

    ; Data from Local System - Collection
    (:action t1005
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - command_and_control
            ?s2 - command_and_control
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u) 
        )
        :effect (and 
            (has_data ?c)
            (not (at ?s1))
            (at ?s2)
        )
    )


    ; Data Obfuscation Steganography - Command and Control 
    (:action t1001_002
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - command_and_control
            ?s2 - act_on_objective
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u)
            (has_data ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (at goal)
        )
    )


    ; Drive-by Compromise - Initial Access 
    (:action t1189
        :parameters (
            ?s1 - initial_access
            ?s2 - installation
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_exploitable ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (malware_running ?c)
        )
    )

    ; Event Triggered Execution: Accessibility Features - Persistence - Privilege Escalation
    (:action t1546_008
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - exploitation
            ?s2 - exploitation
            ?s3 - installation
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (at ?s2)
            (is_exploitable ?c)
        )
        :effect (and 
            (not (at ?s1))
            (not (at ?s2))
            (is_root ?a ?u)
            (when (has_vulnerability ?c) (and 
                    (is_root ?a ?u)
                    (at ?s3)
                )
            )
            (when (not (has_vulnerability ?c))  
                    (at ?s2)
            )
        )
    )


    ; Exploit Public-Facing Application - Intial Access
    (:action t1190
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - initial_access
            ?s2 - exploitation
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_exploitable ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (knows_user ?a ?u)
        )
    )


    ; Exploitation for Client Execution - Execution 
    (:action t1203
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - installation
            ?s2 - command_and_control
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (malware_running ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (is_root ?a ?u)
        )
    )


    ; OS Credential Dumping - Credential Access
    (:action t1003
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - credential_access
            ?s2 - lateral_movement
            ?c - computer
            
        )
        :precondition (and 
            (at ?s1)
            (is_root ?u ?a)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (knows_user ?a ?u)  
        )
    )


    ; Remote Service Session Hijacking: RDP Hijacking - Lateral Movement
    (:action t1563_002
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - lateral_movement
            ?s2 - credential_access
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_exploitable ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (is_root ?u ?a)
        )
    )


    ; Remote Services: Remote Desktop Protocol - Lateral Movement
    (:action t1021_001
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - lateral_movement
            ?s2 - credential_access
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (laterally_moved ?a ?u)
        )
    )


    ; Active Scanning - Reconnaissance 
    (:action t1595
        :parameters (
            ?s1 - reconnaissance
            ?s2 - resource_development
            ?c - computer
            ?n - network
        )
        :precondition (and 
            (at ?s1)
        )
        :effect (and 
            (network_scanned ?n)
            (is_exploitable ?c)
            (not (at ?s1))
            (at ?s2)
        )
    )

; metador

    ; Application Layer Protocol: Web Protocols - Command and Control
    (:action t1071_001
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - command_and_control
            ?s2 - act_on_objective
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (has_system_access ?a ?c)
            (malware_running ?c)
            (gained_persistence ?a ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (at goal)
        )
    )



    ; Event Triggered Execution: Windows Management Instrumentation Event Subscription - Persistence
    (:action t1546_003
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - exploitation
            ?s2 - installation
            ?s3 - initial_access
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
        )
        :effect (and 
            (not (at ?s1))
            (not (at ?s2))
            (is_root ?a ?u)
            (when (has_vulnerability ?c) (and 
                    (is_root ?a ?u)
                    (at ?s3)
                )
            )
            (when (not (has_vulnerability ?c))  
                    (at ?s2)
            )
        )
    )


    ; Ingress Tool Transfer - Command and Control
    (:action t1105
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - command_and_control
            ?s2 - act_on_objective
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u)
            (has_data ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (at goal)
        )
    )

    ; Non-Aplication Layer Protocol - Command and Control
    (:action t1071_002
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - command_and_control
            ?s2 - act_on_objective
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u)
            (has_data ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (c2_channel ?c)
            (at goal)
        )
    )


    ; Obtain Capabilities: Malware - Resource Development
    (:action t1588_001
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - resource_development
            ?s2 - initial_access
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_exploitable ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (malware_running ?c)
            (has_credential ?a ?u )
        )
    )

    ; Obtain Capabilities: Tool Transfer - Resource Development
    (:action t1588_002
        :parameters (
            ?a - attacker 
            ?u - user 
            ?s1 - resource_development
            ?s2 - initial_access
            ?c - computer
        )
        :precondition (and 
            (at ?s1)
            (is_root ?a ?u)
            (has_data ?c)
        )
        :effect (and 
            (not (at ?s1))
            (at ?s2)
            (installed_tools ?a ?c)
        )
    )
)
