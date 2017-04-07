#!/usr/bin/python

import imp
modules = ['os', 'readline', 'cmd']
for module in modules:
	try:
		imp.find_module(module)
	except ImportError:
		do_something()


from cmd import Cmd
import os

def read_entirely(file):
    with open(file, 'r') as handle:
        return handle.read()




class MyPrompt(Cmd, object):
	def preloop(self):
		print '   _____         _           __         ___ '
		print '  / ___/      __(_)_______  / /__  ____|__ \\'
		print '  \__ \ | /| / / /_  /_  / / / _ \/ ___/_/ /'
		print ' ___/ / |/ |/ / / / /_/ /_/ /  __/ /  / __/ '
		print '/____/|__/|__/_/ /___/___/_/\___/_/  /____/ '
		print '\n'
		print 'List of Available Hooks'
		print '\n'.join(self.AVAILABLE_HOOKS)
		super(MyPrompt, self).preloop()


	def do_q(self, args):
		"""Quits the program."""
		print "Quitting."
		os.remove('Swizzler2.js')
		raise SystemExit

	def do_quit(self, args):
		"""Quits the program."""
		print "Quitting."
		os.remove('Swizzler2.js')
		raise SystemExit


	HOOKS = []
	AVAILABLE_HOOKS = ['CommonCrypto', 'NSURL', 'SSLKillSwitch','LocalAuthenticator']

	HOOK_DICT = {
		'CommonCrypto': 'C.CommonCrypto.js',
		'NSURL': 'Foundation.NSURL.js',
		'SSLKillSwitch': 'SSLKillSwitch.js',
		'LocalAuthenticator': 'LocalAuthentication.LAContext.js'
	}

	def do_hook(self, args):
		"""Enables a hook. hook [function]"""
		print "Hooking " + args + " ..."
		self.HOOKS.append(args)

		result = '\n'.join(read_entirely(self.HOOK_DICT[file]) for file in self.HOOKS)

		with open('Swizzler2.js', 'w') as handle:
			handle.write(result)

		print "\nHooks Active: " + ', '.join(self.HOOKS)


	def do_unhook(self, args):
		"""Disables a hook. unhook [function]"""
		print "Unhooking " + args + " ..."
		self.HOOKS.remove(args)

		result = '\n'.join(read_entirely(self.HOOK_DICT[file]) for file in self.HOOKS)

		with open('Swizzler2.js', 'w') as handle:
			handle.write(result)

		print "\nHooks Active: " + ', '.join(self.HOOKS)


	def complete_hook(self, text, line, begidx, endidx):
		if not text:
			completions = self.AVAILABLE_HOOKS[:]
		else:
			completions = [ f
							for f in self.AVAILABLE_HOOKS
							if f.startswith(text)
			]
		return completions


	def complete_unhook(self, text, line, begidx, endidx):
		if not text:
			completions = self.AVAILABLE_HOOKS[:]
		else:
			completions = [ f
							for f in self.AVAILABLE_HOOKS
							if f.startswith(text)
			]
		return completions



	def do_list(self, args):
		"""List available or active hooks."""
		args = args.split()
		
		if len(args) != 2:
			print "list hooks available"
			print "list hooks active"
			return

		if args[1] == 'available':
			print '\n'.join(self.AVAILABLE_HOOKS)

		if args[1] == 'active':
			print '\n'.join(self.HOOKS)





if __name__ == '__main__':
	prompt = MyPrompt()
	prompt.prompt = '# '
	prompt.cmdloop()


