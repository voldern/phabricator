<?php

/*
 * Copyright 2012 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

final class PhabricatorLDAPRegistrationController
extends PhabricatorAuthController {
  private $ldapProvider;
  private $ldapInfo;

  public function setLDAPProvider($provider) {
    $this->ldapProvider = $provider;
    return $this;
  }

  public function getLDAProvider() {
    return $this->ldapProvider;
  }

  public function setLDAPInfo($info) {
    $this->ldapInfo = $info;
    return $this;
  }

  public function getLDAPInfo() {
    return $this->ldapInfo;
  }

  public function processRequest() {
    $provider = $this->getLDAProvider();
    $ldap_info = $this->getLDAPInfo();
    $request = $this->getRequest();

    $errors = array();
    $e_username = true;
    $e_email = true;
    $e_realname = true;
    
    $user = new PhabricatorUser();
    $user->setUsername();
    $user->setRealname($provider->retrieveUserRealName());

    $new_email = $provider->retrieveUserEmail();
    
    if ($request->isFormPost()) {
      $user->setUsername($request->getStr('username'));
      $username = $user->getUsername();
      if (!strlen($user->getUsername())) {
        $e_username = 'Required';
        $errors[] = 'Username is required.';
      } else if (!PhabricatorUser::validateUsername($username)) {
        $e_username = 'Invalid';
        $errors[] = 'Username must consist of only numbers and letters.';
      } else {
        $e_username = null;
      }

      if (!$new_email) {
        $new_email = trim($request->getStr('email'));
        if (!$new_email) {
          $e_email = 'Required';
          $errors[] = 'Email is required.';
        } else {
          $e_email = null;
        }
      }

      // get real name from LDAP
      //$user->setRealName();

      if (!strlen($user->getRealName())) {
        $user->setRealName($request->getStr('realname'));
        if (!strlen($user->getRealName())) {
          $e_realname = 'Required';
          $errors[] = 'Real name is required.';
        } else {
          $e_realname = null;
        }
      }

      if (!$errors) {
        try {                    
          // NOTE: We don't verify LDAP email addresses by default because
          // LDAP providers might associate email addresses with accounts that
          // haven't actually verified they own them. We could selectively
          // auto-verify some providers that we trust here, but the stakes for
          // verifying an email address are high because having a corporate
          // address at a company is sometimes the key to the castle.

          $email_obj = id(new PhabricatorUserEmail())
            ->setAddress($new_email)
            ->setIsVerified(0);

          id(new PhabricatorUserEditor())
            ->setActor($user)
            ->createNewUser($user, $email_obj);

          $ldap_info->setUserID($user->getID());
          $ldap_info->save();

          $session_key = $user->establishSession('web');
          $request->setCookie('phusr', $user->getUsername());
          $request->setCookie('phsid', $session_key);

          $email_obj->sendVerificationEmail($user);
          
          return id(new AphrontRedirectResponse())->setURI('/');
        } catch (AphrontQueryDuplicateKeyException $exception) {

          $same_username = id(new PhabricatorUser())->loadOneWhere(
            'userName = %s',
            $user->getUserName());

          $same_email = id(new PhabricatorUserEmail())->loadOneWhere(
            'address = %s',
            $new_email);

          if ($same_username) {
            $e_username = 'Duplicate';
            $errors[] = 'That username or email is not unique.';
          } else if ($same_email) {
            $e_email = 'Duplicate';
            $errors[] = 'That email is not unique.';
          } else {
            throw $exception;
          }
        }
      }
    }


    $error_view = null;
    if ($errors) {
      $error_view = new AphrontErrorView();
      $error_view->setTitle('Registration Failed');
      $error_view->setErrors($errors);
    }

    // Strip the URI down to the path, because otherwise we'll trigger
    // external CSRF protection (by having a protocol in the form "action")
    // and generate a form with no CSRF token.
    $action_uri = new PhutilURI('/ldap/login/');
    $action_path = $action_uri->getPath();

    $form = new AphrontFormView();
    $form
      ->setUser($request->getUser())
      ->setAction($action_path)
      ->appendChild(
        id(new AphrontFormTextControl())
        ->setLabel('Username')
        ->setName('username')
        ->setValue($user->getUsername())
        ->setError($e_username));

    $form->appendChild(
      id(new AphrontFormPasswordControl())
        ->setLabel('Password')
        ->setName('password'));

    if ($provider->retrieveUserEmail() === null) {
      $form->appendChild(
        id(new AphrontFormTextControl())
        ->setLabel('Email')
        ->setName('email')
        ->setValue($request->getStr('email'))
        ->setError($e_email));
    }

    if ($provider->retrieveUserRealName() === null) {
      $form->appendChild(
        id(new AphrontFormTextControl())
        ->setLabel('Real Name')
        ->setName('realname')
        ->setValue($request->getStr('realname'))
        ->setError($e_realname));
    }

    $form
      ->appendChild(
        id(new AphrontFormSubmitControl())
        ->setValue('Create Account'));

    $panel = new AphrontPanelView();
    $panel->setHeader('Create New Account');
    $panel->setWidth(AphrontPanelView::WIDTH_FORM);
    $panel->appendChild($form);

    return $this->buildStandardPageResponse(
      array(
        $error_view,
        $panel,
      ),
      array(
        'title' => 'Create New Account',
      ));
  }

}
