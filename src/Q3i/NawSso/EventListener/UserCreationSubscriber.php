<?php
/**
 * Created by IntelliJ IDEA.
 * User: Artek
 * Date: 09.11.2016
 * Time: 16:33
 */

namespace Q3i\NawSso\EventListener;

/**
 * @ignore
 */
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class UserCreationSubscriber
 * @package Q3i\NawSso\EventListener
 */
class UserCreationSubscriber implements EventSubscriberInterface
{
    /**
     * @return array
     */
    static public function getSubscribedEvents()
    {
        return array(
            'q3i.naw_sso.username_taken'	=> 'onUsernameTaken'
        );
    }
    
    public function onUsernameTaken($event) {
        
    }

}