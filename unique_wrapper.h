/**
 *  Copyright (C) 2023 James Williams
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

#pragma once
#include <functional>

template <typename T>
struct UniqueWrapper {
	UniqueWrapper(T v, std::function<void(T)> d);

	~UniqueWrapper();

	// copy
	UniqueWrapper(const  UniqueWrapper<T>&) = delete;
	UniqueWrapper& operator=(const  UniqueWrapper<T>&) = delete;

	// move
	UniqueWrapper(UniqueWrapper<T>&&) = default;
	UniqueWrapper& operator=(UniqueWrapper<T>&&) = default;

	T get();

	operator T() const;

private:
	T value;
	std::function<void(T)> deleter;
};

template <typename T>
UniqueWrapper<T>::UniqueWrapper(T v, std::function<void(T)> d) : value(v), deleter(std::move(d)) { }

template <typename T>
UniqueWrapper<T>::~UniqueWrapper() {
	deleter(value);
}

template <typename T>
T UniqueWrapper<T>::get() {
	return value;
}

template <typename T>
UniqueWrapper<T>::operator T() const {
	return value;
}


