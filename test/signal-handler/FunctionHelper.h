#ifndef FUNCTION_HELPER_H_
#define FUNCTION_HELPER_H_

// This header file should not be included in any file except in SignalHandler.h file
#ifndef SIGNAL_HANDLER_H_
#error "FunctionHelper.h" should be included only in "SignalHandler.h" file!
#endif

/// Includes needed functions for use in Signal Handler library

#include <functional>

namespace
{

template <const size_t UniqueId, typename Result, typename... ArgumentTypes>
class FunctionPointerHelper
{
public:
	typedef std::function<Result(ArgumentTypes...)> FunctionType;

	static void bind(FunctionType&& f)
	{
		instance().function_pointer.swap(f);
	}

	static void bind(const FunctionType& f)
	{
		instance().function_pointer = f;
	}

	static Result invoke(ArgumentTypes... args)
	{
		return instance().function_pointer(args...);
	}

	typedef decltype(&FunctionPointerHelper::invoke) pointer_type;

	static pointer_type ptr()
	{
		return &invoke;
	}

private:
	static FunctionPointerHelper& instance()
	{
		static FunctionPointerHelper my_instance;
		return my_instance;
	}

	FunctionPointerHelper() = default;

	FunctionType function_pointer;
};

/**
 * This function converts a pointer member function to a function pointer
 *
 * @param input_function member function pointer
 * @param UniqueId template parameter used to state the member function chronological number
 * @return function pointer
 */
template <const size_t UniqueId, typename Result, typename... ArgumentTypes>
typename FunctionPointerHelper<UniqueId, Result, ArgumentTypes...>::pointer_type
get_function_pointer(const std::function<Result(ArgumentTypes...)>& input_function)
{
	FunctionPointerHelper<UniqueId, Result, ArgumentTypes...>::bind(input_function);
	return FunctionPointerHelper<UniqueId, Result, ArgumentTypes...>::ptr();
}

template <typename T>
std::function<typename std::enable_if<std::is_function<T>::value, T>::type>
make_function(T *t)
{
	return {t};
}

}

#endif
