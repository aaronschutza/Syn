c = get_config()
# Force Voila to listen on all interfaces
c.VoilaApp.ip = '0.0.0.0'
c.VoilaApp.port = 8866
c.VoilaApp.open_browser = False