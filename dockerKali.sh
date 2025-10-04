# 1. Update package index & install prerequisites
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# 2. Add Docker’s GPG key & repository
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Use “$(lsb_release -cs)” but ensure it maps well because Kali is a Debian derivative
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" |
  sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

# 3. Update apt with Docker repo & install Docker CE
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# 4. Start & enable Docker daemon
sudo systemctl enable docker
sudo systemctl start docker

# 5. Optionally, allow your user to run docker without sudo
sudo usermod -aG docker $USER
# Then log out & log back in (or reboot) so group change applies.
