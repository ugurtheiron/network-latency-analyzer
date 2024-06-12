project('dpdk_app', 'c', default_options : ['default_library=static'])

dpdk_dep = dependency('libdpdk', version : '>=23.11', required : true)
executable('network_latency_analyzer', 'main.c', dependencies : dpdk_dep)
