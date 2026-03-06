# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-22.04"

  config.vm.define "omegle-app" do |node|
    node.vm.hostname = "omegle-app"
    node.vm.network "private_network", ip: "192.168.56.30"

    # Accès depuis le navigateur host
    node.vm.network "forwarded_port", guest: 3000, host: 3000  # App web
    node.vm.network "forwarded_port", guest: 3001, host: 3001  # Socket.io (si port séparé)
    node.vm.network "forwarded_port", guest: 3443, host: 3443

    node.vm.provider "virtualbox" do |v|
      v.memory = 1024   # 1 Go suffit largement
      v.cpus   = 2
      v.name   = "omegle-app"
    end

    # Provisioning automatique : Node.js + Git
    node.vm.provision "shell", inline: <<-SHELL
      apt-get update -y
      apt-get install -y curl git build-essential

      # Node.js 20 LTS
      curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
      apt-get install -y nodejs

      echo "✅ Node $(node -v) installé"
      echo "✅ npm $(npm -v) installé"
    SHELL
  end
end