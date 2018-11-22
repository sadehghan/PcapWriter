#include "SignalHandler.h"

bool SignalHandler::add_handler_to_signals(void(*handler)(int), std::initializer_list<int> signals_list)
{
	for (int signal_type : signals_list)
		if (!add_handler_to_signals(handler, signal_type))
			return false;

	return true;
}

bool SignalHandler::add_handler_to_signals(void(*handler)(int), int signal_type)
{
	struct sigaction act;
	memset (&act, '\0', sizeof(act));
	act.sa_handler = handler;

	if (sigaction(signal_type, &act, NULL) < 0)
		return false;

	return true;
}
