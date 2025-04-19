
export const register_me = async (formData) => {
    try {
        const res = await fetch(`/api/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.message || 'Registration failed');
        }

        const data = await res.json();
        return data;
    } catch (error) {
        console.log('Error in register (service):', error.message);
        return { error: error.message };
    }
};


export const login_me = async (formData) => {
    try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        })
        const data = res.json();
        return data;
    } catch (error) {
        console.log('error in login (service) => ', error);
    }
}



export const forget_password = async (formData) => {
    try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/forgetPassword`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        })
        const data = res.json();
        return data;
    } catch (error) {
        console.log('error in forget Password (service) => ', error);
    }
}

