<?php

namespace LP\TwoFA\Http\Controllers\TwoFA;


use App\Models\User;
use Illuminate\Http\JsonResponse;
use LP\TwoFA\Contracts\TwoFaAuthInterface;
use LP\TwoFA\Http\Controllers\Controller;
use LP\TwoFA\Http\Request\AuthRequest;

class AuthTwoFAController extends Controller
{

    public function __construct(private TwoFaAuthInterface $authentication)
    {
        parent::__construct();
    }

    public function store(AuthRequest $request)
    {
        if ($this->verify($request)) {
            $authEnable = $this->user->update(
                [
                    'google2fa_enable' => true,
                ]
            );
            return response()->json(
                [
                    'enabled' => $authEnable,
                ]
            );
        } else {
            return response()->json('invalid code');
        }
    }


    /**
     * @param User $user
     * @param AuthRequest $request
     * @return array|JsonResponse
     */
    public function destroy(User $user, AuthRequest $request): array|JsonResponse
    {
        $flag = false;

        if (is_null($user->google2fa_secret)) {
            return [];
        }

        if ($this->authentication->validRecoveryCode($request->get('code'), $this->user)) {
            $user->replaceRecoveryCode($request->get('code'));
            $flag = true;
        } elseif ($this->authentication->verify(decrypt($user->google2fa_secret), $request->get('code'))) {
            $flag = true;
        }

        if ($flag) {
            $isDisabled = $user->disable2fa();
            return response()->json(
                [
                    "disabled" => $isDisabled,
                ]
            );
        } else {
            return response()->json('invalid code');
        }
    }

    /**
     * @param AuthRequest $request
     * @return bool|JsonResponse
     */
    public function verify(AuthRequest $request): bool|JsonResponse
    {
        if ($this->authentication->verify(decrypt($this->user->google2fa_secret), $request->code)) {
            return true;
        }
        return false;
    }

    public function getTwoFactorAuthEnabledStatus() {
        $google2fa_enable_status = $this->user->google2fa_enable;

        return $google2fa_enable_status;
    }

    /**
     * @param AuthRequest $request
     * @return bool|JsonResponse
     */
    public function verifyOTPEnableTwoFactorAuth(AuthRequest $request): bool|JsonResponse
    {
        if ($this->authentication->verify(decrypt($this->user->google2fa_secret), $request->code)) {

            $this->user->google2fa_enable = true;
            $this->user->save();

            return response()->json(
                [
                    'enabled' => $this->user->google2fa_enable,
                ]
            );
        }
        return response()->json('invalid code');
    }

    /**
     * @param AuthRequest $request
     * @return bool|JsonResponse
     */
    public function verifyOTPDisableTwoFactorAuth(AuthRequest $request): bool|JsonResponse
    {
        $flag = false;

        if ($this->authentication->verify(decrypt($this->user->google2fa_secret), $request->code)) {
            $flag = true;
        } elseif ($this->authentication->validRecoveryCode($request->get('code'), $this->user)) {
            $flag = true;
        }

        if ($flag) {
            $this->user->google2fa_enable = false;
            $this->user->save();
            return response()->json(
                [
                    'enabled' => $this->user->google2fa_enable,
                ]
            );
        }

        return response()->json('invalid code');
    }
}
