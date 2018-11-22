#ifndef SIGNAL_HANDLER_H_
#define SIGNAL_HANDLER_H_

#include <csignal>
#include <cstring>

#include <functional>
#include <initializer_list>
#include <type_traits>

/// The class which contains a static function for associating signals to a handler
class SignalHandler
{
	template <typename ClassType>
	using HandlerType = void (ClassType::*)(int);

public:
	/**
	 * This function adds a class function as a handler to a list of signals.
	 *
	 * @param UniqueId template parameter used to state the member function chronological number. It must be unique. It
	 * 		is memory efficient to use sequential numbers.
	 * @param signal_handled_class class instance which function member will be assigned as handler
	 * @param typename HandlerType<ClassType>::VALUE reference to class member function
	 * @param signals_list The list of signals we want the handler to add to.
	 * @return true if it could associate the signal handler to the signal, otherwise false.
	 */
	template <const size_t UniqueId, typename ClassType>
	inline static bool add_handler_to_signals(ClassType& signal_handled_class, HandlerType<ClassType>,
			std::initializer_list<int> signals_list);

	/**
	 * This function adds the stated handler to a list of signals.
	 * 
	 * @param handler The function which gets added to the list of signals.
	 * @param signals_list The list of signals we want the handler to add to.
	 * @return true if it could associate the signal handler to the signal, otherwise false.
	 */
	static bool add_handler_to_signals(void(*handler)(int), std::initializer_list<int> signals_list);

	/**
	 * This function adds the stated handler to the signal.
	 * 
	 * @param handler The function which gets added to the list of signals.
	 * @param signal_type The signal we want the handler to add to.
	 * @return true if it could associate the signal handler to the signal, otherwise false.
	 */
	static bool add_handler_to_signals(void(*handler)(int), int signal_type);
};

#include "FunctionHelper.h"

template <const size_t UniqueId, typename ClassType>
bool SignalHandler::add_handler_to_signals(ClassType& signal_handled_class,
	HandlerType<ClassType> handler, std::initializer_list<int> signals_list)
{
	typedef HandlerType<ClassType> HandlerType;

	static_assert(std::is_member_function_pointer<HandlerType>::value, "Class does not contain member.");

	return add_handler_to_signals(get_function_pointer<UniqueId>(std::function<void(int)>(
					std::bind([](ClassType& self, HandlerType handler, int sig){ (self.*handler)(sig); },
						std::ref(signal_handled_class), handler, std::placeholders::_1))), signals_list);
}

#endif
