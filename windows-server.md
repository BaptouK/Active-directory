# Windows server

Script d'installation d'un AD

```javascript

#
# Script Windows PowerShell pour le déploiement d'AD DS
#

Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "baptouk.loc" `
-DomainNetbiosName "BAPTOUK" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
```

Script de base pour rejoindre un AD

```javascript
#
# Script Windows PowerShell pour le déploiement d'AD DS
#

Import-Module ADDSDeployment
Install-ADDSDomainController `
-NoGlobalCatalog:$false `
-CreateDnsDelegation:$false `
-Credential (Get-Credential) `
-CriticalReplicationOnly:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainName "baptouk.loc" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SiteName "Default-First-Site-Name" `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
```

Pour copier coller dans VM mettre insérer disque → vbox driver chelou

pour déverouiller le pc en VM : menu input→ keyboard insert+supr+del

# Script pour créer un AD

```powershell
$hostname = "AD1"
$ipv4 = "192.168.56.21"
$dns = $ipv4
$dns_auxiliaire = "8.8.8.8"
$submask = "24" #nombre de bits allouer au submask (24 pour 255.255.255.0)
$domainName = "baptiste.local"
$domainNetBios = "BAPTISTE"
$nomPC = (Get-WMIObject -Class Win32_ComputerSystem).Name


if ($nomPC -eq $hostname){
    # Récupère l'interface utilisée pour accéder à internet
    $interface_id = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -ExpandProperty ifIndex
    echo $interface_id


    $ipactuel = Get-NetIPAddress -InterfaceIndex $interface_id
    $IPexist = $ipactuel | Where-Object {$_.AddressFamily -eq "IPv4"}

    if ($ipactuel){
      echo "IP deja configuré"
    }else {
    # Change l'IP en fixe
    New-NetIPAddress -InterfaceIndex $interface_id -IPAddress $ipv4 -PrefixLength $submask
    }

    $dnsactuel = Get-DnsClientServerAddress -InterfaceIndex $interface_id

    $dnsexist = $dnsactuel.ServerAddress -contains $dns

    if ($dnsexist){
      echo "Serveur principal deja configuré à $dns"
    }else{
        # Configure les serveurs DNS
        Set-DnsClientServerAddress -InterfaceIndex $interface_id -ServerAddresses $dns, $dns_auxiliaire
    }

    if ((Get-ADForest).Name -eq $domainName){
        echo "La foret $domainName existe deja"
    }else {

        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

        Import-Module ADDSDeployment
        Install-ADDSForest `
            -CreateDnsDelegation:$false `
            -DatabasePath "C:\Windows\NTDS" `
            -DomainMode "WinThreshold" `
            -DomainName $domainName `
            -DomainNetbiosName $domainNetBios `
            -ForestMode "WinThreshold" `
            -InstallDns:$true `
            -LogPath "C:\Windows\NTDS" `
            -NoRebootOnCompletion:$false `
            -SysvolPath "C:\Windows\SYSVOL" `
            -Force:$true
    }

}else{
    Rename-Computer -NewName $hostname
    Restart-Computer
}
```

### Pour tester si tout fonctionne :

`Get-Service adws,kdc,netlogon,dns`

`Get-ADDomainController`

`Get-ADDomain baptiste.local`

Pour changer le UUID, important si c'est un clone d'une VM

`C:\Windows\System32\sysprep\sysprep.exe /oobe /generalize`

# Script pour rejoindre un AD

```powershell
$hostname = "AD2"
$ipv4 = "192.168.56.22"
$dns = "192.168.56.21"
$dns_auxiliaire = "127.0.0.1"
$submask = "24" # Nombre de bits alloués au masque (24 pour 255.255.255.0)
$domainName = "baptiste.local"
$domainNetBios = "BAPTISTE"
$nomPC = (Get-WMIObject -Class Win32_ComputerSystem).Name

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

if ($nomPC -eq $hostname) {
    # Récupère l'interface réseau utilisée
    $interface_id = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -ExpandProperty ifIndex
    echo "Interface réseau ID : $interface_id"

    #Configure l'adresse IP
    $ipactuel = Get-NetIPAddress -InterfaceIndex $interface_id -AddressFamily IPv4
    if ($ipactuel.IPAddress -eq $ipv4) {
        echo "L'adresse IP est déjà configurée : $ipv4"
    } else {
        # Change l'IP en fixe
        New-NetIPAddress -InterfaceIndex $interface_id -IPAddress $ipv4 -PrefixLength $submask -DefaultGateway "192.168.56.1"
    }

    #Configure les serveurs DNS
    $dnsactuel = Get-DnsClientServerAddress -InterfaceIndex $interface_id | Select-Object -ExpandProperty ServerAddresses
    if ($dnsactuel -contains $dns) {
        echo "Serveur DNS principal déjà configuré : $dns"
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $interface_id -ServerAddresses $dns, $dns_auxiliaire
    }

  try{
    Get-ADForest
  }catch{
    # Installer le contrôleur de domaine si nécessaire
    Import-Module ADDSDeployment
    Install-ADDSDomainController `
        -NoGlobalCatalog:$false `
        -CreateDnsDelegation:$false `
        -Credential (Get-Credential) `
        -CriticalReplicationOnly:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainName $domainName `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$false `
        -SiteName "Default-First-Site-Name" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
} else {
    Rename-Computer -NewName $hostname
    Restart-Computer
}
```

# Enroller un client

```bash
# Définition des variables
$DomainName = "baptiste.local"
$AdminUser = "BAPTISTE\Administrateur"  # Remplacez par un compte administrateur du domaine
$Password = Read-Host "Entrez le mot de passe de l'administrateur du domaine" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential ($AdminUser, $Password)

$dns = "192.168.56.21"
$dns_auxiliaire = "127.0.0.1"
$interface_id = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -ExpandProperty ifIndex

#Configure les serveurs DNS
$dnsactuel = Get-DnsClientServerAddress -InterfaceIndex $interface_id | Select-Object -ExpandProperty ServerAddresses
if ($dnsactuel -contains $dns) {
    echo "Serveur DNS principal déjà configuré : $dns"
} else {
    Set-DnsClientServerAddress -InterfaceIndex $interface_id -ServerAddresses $dns, $dns_auxiliaire
}

# Vérifier si la machine est déjà membre du domaine
$ComputerInfo = Get-WmiObject Win32_ComputerSystem
if ($ComputerInfo.PartOfDomain -eq $false) {
    # Ajouter la machine au domaine
    Add-Computer -DomainName $DomainName -Credential $Credential -Force -Restart
    Write-Host "La machine a été ajoutée au domaine '$DomainName'. Redémarrage en cours..."
} else {
    Write-Host "La machine est déjà membre du domaine '$DomainName'."
}
```

# Création d'OU, user, groupe, dossier partagé, gpo

```bash
# Définition des variables
$NomGroupe = "GroupeIT"
$NomUtilisateur = "jdupont"
$Prenom = "Jean"
$Nom = "Dupont"
$MotDePasse = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$OU = "OU=UserAccounts,DC=baptiste,DC=local"
$DossierPartage = "C:\PartageIT"
$NomPartage = "PartageIT"

#Création d'un OU
New-ADOrganizationalUnit -Name "UserAccounts" -Path "DC=baptiste,DC=local"

# Créer un groupe
New-ADGroup -Name $NomGroupe -SamAccountName $NomGroupe -GroupCategory Security -GroupScope Global -Path $OU

# Créer un utilisateur
New-ADUser -Name "$Prenom $Nom" -GivenName $Prenom -Surname $Nom `
-UserPrincipalName "$NomUtilisateur@baptiste.local" `
-SamAccountName $NomUtilisateur -AccountPassword $MotDePasse `
-Path $OU -Enabled $true

# Ajout de l'utilisateur au groupe
Add-ADGroupMember -Identity $NomGroupe -Members $NomUtilisateur

# Créer un dossier partagé
if (!(Test-Path $DossierPartage)) {
    New-Item -Path $DossierPartage -ItemType Directory
}

# Partage du dossier sur le réseau
New-SmbShare -Name $NomPartage -Path $DossierPartage -FullAccess "Administrateurs"

# Attribution des permissions NTFS au Groupe
$ACL = Get-Acl $DossierPartage
$Permission = New-Object System.Security.AccessControl.FileSystemAccessRule("$NomGroupe", "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
$ACL.SetAccessRule($Permission)
Set-Acl $DossierPartage $ACL

Import-Module GroupPolicy

$GPOName = "RestrictionsAcces"

# Créer une nouvelle GPO
New-GPO -Name $GPOName

# Désactiver l'accès à l'invite de commandes
Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Policies\Microsoft\Windows\PowerShell" -ValueName "ExecutionPolicy" -Type String -Value "Restricted"

# Bloquer l'accès au jeu Solitaire
Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "DisallowRun" -Type String -Value "1"
Set-GPRegistryValue -Name $GPOName -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -ValueName "1" -Type String -Value "solitaire.exe"

New-GPLink -Name $GPOName -Target $OU
Invoke-GPUpdate -Computer "NomDeLOrdinateurCible" -Force
```
