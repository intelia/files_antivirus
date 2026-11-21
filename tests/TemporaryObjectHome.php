<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Files_Antivirus\Tests;

/**
 * A temporary storage with the id of a home storage in a primary object store
 */
class TemporaryObjectHome extends \OC\Files\Storage\Temporary {
	private string $id;

	public function __construct($arguments = []) {
		parent::__construct($arguments);
		$this->id = uniqid();
	}

	public function getId(): string {
		return 'object::user:' . $this->id;
	}
}
